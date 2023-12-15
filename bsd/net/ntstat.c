/*
 * Copyright (c) 2010-2021 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/mcache.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/persona.h>

#include <kern/clock.h>
#include <kern/debug.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/locks.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/dlil.h>

// These includes appear in ntstat.h but we include them here first so they won't trigger
// any clang diagnostic errors.
#include <netinet/in.h>
#include <netinet/in_stat.h>
#include <netinet/tcp.h>

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"
#pragma clang diagnostic error "-Wpacked"
// This header defines structures shared with user space, so we need to ensure there is
// no compiler inserted padding in case the user space process isn't using the same
// architecture as the kernel (example: i386 process with x86_64 kernel).
#include <net/ntstat.h>
#pragma clang diagnostic pop

#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_cc.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/in6_var.h>

__private_extern__ int  nstat_collect = 1;

#if (DEBUG || DEVELOPMENT)
SYSCTL_INT(_net, OID_AUTO, statistics, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_collect, 0, "Collect detailed statistics");
#endif /* (DEBUG || DEVELOPMENT) */

#if !XNU_TARGET_OS_OSX
static int nstat_privcheck = 1;
#else /* XNU_TARGET_OS_OSX */
static int nstat_privcheck = 0;
#endif /* XNU_TARGET_OS_OSX */
SYSCTL_INT(_net, OID_AUTO, statistics_privcheck, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_privcheck, 0, "Entitlement check");

SYSCTL_NODE(_net, OID_AUTO, stats,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "network statistics");

static int nstat_debug = 0;
SYSCTL_INT(_net_stats, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_debug, 0, "");

static int nstat_debug_pid = 0; // Only log socket level debug for specified pid
SYSCTL_INT(_net_stats, OID_AUTO, debug_pid, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_debug_pid, 0, "");

static int nstat_sendspace = 2048;
SYSCTL_INT(_net_stats, OID_AUTO, sendspace, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_sendspace, 0, "");

static int nstat_recvspace = 8192;
SYSCTL_INT(_net_stats, OID_AUTO, recvspace, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_recvspace, 0, "");

static struct nstat_stats nstat_stats;
SYSCTL_STRUCT(_net_stats, OID_AUTO, stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &nstat_stats, nstat_stats, "");

static u_int32_t nstat_lim_interval = 30 * 60; /* Report interval, seconds */
static u_int32_t nstat_lim_min_tx_pkts = 100;
static u_int32_t nstat_lim_min_rx_pkts = 100;
#if (DEBUG || DEVELOPMENT)
SYSCTL_INT(_net_stats, OID_AUTO, lim_report_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nstat_lim_interval, 0,
    "Low internet stat report interval");

SYSCTL_INT(_net_stats, OID_AUTO, lim_min_tx_pkts,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nstat_lim_min_tx_pkts, 0,
    "Low Internet, min transmit packets threshold");

SYSCTL_INT(_net_stats, OID_AUTO, lim_min_rx_pkts,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nstat_lim_min_rx_pkts, 0,
    "Low Internet, min receive packets threshold");
#endif /* DEBUG || DEVELOPMENT */

static struct net_api_stats net_api_stats_before;
static u_int64_t net_api_stats_last_report_time;
#define NET_API_STATS_REPORT_INTERVAL (12 * 60 * 60) /* 12 hours, in seconds */
static u_int32_t net_api_stats_report_interval = NET_API_STATS_REPORT_INTERVAL;

#if (DEBUG || DEVELOPMENT)
SYSCTL_UINT(_net_stats, OID_AUTO, api_report_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &net_api_stats_report_interval, 0, "");
#endif /* DEBUG || DEVELOPMENT */

#define NSTAT_DEBUG_SOCKET_PID_MATCHED(so) \
    (so && (nstat_debug_pid == (so->so_flags & SOF_DELEGATED ? so->e_pid : so->last_pid)))

#define NSTAT_DEBUG_SOCKET_ON(so) \
    ((nstat_debug && (!nstat_debug_pid || NSTAT_DEBUG_SOCKET_PID_MATCHED(so))) ? nstat_debug : 0)

#define NSTAT_DEBUG_SOCKET_LOG(so, fmt, ...)                                                                    \
    if (NSTAT_DEBUG_SOCKET_ON(so)) {                                                                            \
	printf("NSTAT_DEBUG_SOCKET <pid %d>: " fmt "\n", (so->so_flags & SOF_DELEGATED ? so->e_pid : so->last_pid), ##__VA_ARGS__); \
    }

enum{
	NSTAT_FLAG_CLEANUP              = (1 << 0),
	NSTAT_FLAG_REQCOUNTS            = (1 << 1),
	NSTAT_FLAG_SUPPORTS_UPDATES     = (1 << 2),
	NSTAT_FLAG_SYSINFO_SUBSCRIBED   = (1 << 3),
};

#if !XNU_TARGET_OS_OSX
#define QUERY_CONTINUATION_SRC_COUNT 50
#else /* XNU_TARGET_OS_OSX */
#define QUERY_CONTINUATION_SRC_COUNT 100
#endif /* XNU_TARGET_OS_OSX */

#ifndef ROUNDUP64
#define ROUNDUP64(x) P2ROUNDUP((x), sizeof (u_int64_t))
#endif

#ifndef ADVANCE64
#define ADVANCE64(p, n) (void*)((char *)(p) + ROUNDUP64(n))
#endif

typedef TAILQ_HEAD(, nstat_src)     tailq_head_nstat_src;
typedef TAILQ_ENTRY(nstat_src)      tailq_entry_nstat_src;

typedef TAILQ_HEAD(, nstat_tu_shadow)   tailq_head_tu_shadow;
typedef TAILQ_ENTRY(nstat_tu_shadow)    tailq_entry_tu_shadow;

typedef TAILQ_HEAD(, nstat_generic_shadow) tailq_head_generic_shadow;
typedef TAILQ_ENTRY(nstat_generic_shadow)  tailq_entry_generic_shadow;

typedef TAILQ_HEAD(, nstat_procdetails) tailq_head_procdetails;
typedef TAILQ_ENTRY(nstat_procdetails)  tailq_entry_procdetails;

struct nstat_procdetails {
	tailq_entry_procdetails         pdet_link;
	int                             pdet_pid;
	u_int64_t                       pdet_upid;
	char                            pdet_procname[64];
	uuid_t                          pdet_uuid;
	u_int32_t                       pdet_refcnt;
	u_int32_t                       pdet_magic;
};

typedef struct nstat_provider_filter {
	u_int64_t                       npf_flags;
	u_int64_t                       npf_events;
	u_int64_t                       npf_extensions;
	pid_t                           npf_pid;
	uuid_t                          npf_uuid;
} nstat_provider_filter;


typedef struct nstat_control_state {
	struct nstat_control_state      *ncs_next;
	/* A bitmask to indicate whether a provider ever done NSTAT_MSG_TYPE_ADD_ALL_SRCS */
	u_int32_t               ncs_watching;
	/* A bitmask to indicate whether a provider ever done NSTAT_MSG_TYPE_ADD_SRC */
	u_int32_t               ncs_added_src;
	decl_lck_mtx_data(, ncs_mtx);
	kern_ctl_ref            ncs_kctl;
	u_int32_t               ncs_unit;
	nstat_src_ref_t         ncs_next_srcref;
	tailq_head_nstat_src    ncs_src_queue;
	mbuf_t                  ncs_accumulated;
	u_int32_t               ncs_flags;
	nstat_provider_filter   ncs_provider_filters[NSTAT_PROVIDER_COUNT];
	/* state maintained for partial query requests */
	u_int64_t               ncs_context;
	u_int64_t               ncs_seq;
	/* For ease of debugging with lldb macros */
	struct nstat_procdetails *ncs_procdetails;
} nstat_control_state;

typedef struct nstat_provider {
	struct nstat_provider   *next;
	nstat_provider_id_t     nstat_provider_id;
	size_t                  nstat_descriptor_length;
	errno_t                 (*nstat_lookup)(const void *data, u_int32_t length, nstat_provider_cookie_t *out_cookie);
	int                     (*nstat_gone)(nstat_provider_cookie_t cookie);
	errno_t                 (*nstat_counts)(nstat_provider_cookie_t cookie, struct nstat_counts *out_counts, int *out_gone);
	errno_t                 (*nstat_watcher_add)(nstat_control_state *state, nstat_msg_add_all_srcs *req);
	void                    (*nstat_watcher_remove)(nstat_control_state *state);
	errno_t                 (*nstat_copy_descriptor)(nstat_provider_cookie_t cookie, void *data, size_t len);
	void                    (*nstat_release)(nstat_provider_cookie_t cookie, boolean_t locked);
	bool                    (*nstat_reporting_allowed)(nstat_provider_cookie_t cookie, nstat_provider_filter *filter, u_int64_t suppression_flags);
	bool                    (*nstat_cookie_equal)(nstat_provider_cookie_t cookie1, nstat_provider_cookie_t cookie2);
	size_t                  (*nstat_copy_extension)(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *buf, size_t len);
} nstat_provider;

typedef struct nstat_src {
	tailq_entry_nstat_src   ns_control_link;        // All sources for the nstat_control_state, for iterating over.
	nstat_control_state     *ns_control;            // The nstat_control_state that this is a source for
	nstat_src_ref_t         srcref;
	nstat_provider          *provider;
	nstat_provider_cookie_t cookie;
	uint32_t                filter;
	bool                    ns_reported;            // At least one update/counts/desc message has been sent
	uint64_t                seq;
} nstat_src;

// The merge structures are intended to give a global picture of what may be asked for by the current set of clients
// This is to avoid taking locks to check them all individually
typedef struct nstat_merged_provider_filter {
	u_int64_t               mf_events;      // So far we only merge the events portion of any filters
} nstat_merged_provider_filter;

typedef struct nstat_merged_provider_filters {
	nstat_merged_provider_filter    mpf_filters[NSTAT_PROVIDER_COUNT];
} nstat_merged_provider_filters;

static errno_t      nstat_control_send_counts(nstat_control_state *, nstat_src *, unsigned long long, u_int16_t, int *);
static int          nstat_control_send_description(nstat_control_state *state, nstat_src *src, u_int64_t context, u_int16_t hdr_flags);
static int          nstat_control_send_update(nstat_control_state *state, nstat_src *src, u_int64_t context, u_int64_t event, u_int16_t hdr_flags, int *gone);
static errno_t      nstat_control_send_removed(nstat_control_state *state, nstat_src *src, u_int16_t hdr_flags);
static errno_t      nstat_control_send_goodbye(nstat_control_state  *state, nstat_src *src);
static void         nstat_control_cleanup_source(nstat_control_state *state, nstat_src *src, boolean_t);
static bool         nstat_control_reporting_allowed(nstat_control_state *state, nstat_src *src, u_int64_t suppression_flags);
static boolean_t    nstat_control_begin_query(nstat_control_state *state, const nstat_msg_hdr *hdrp);
static u_int16_t    nstat_control_end_query(nstat_control_state *state, nstat_src *last_src, boolean_t partial);
static void         nstat_ifnet_report_ecn_stats(void);
static void         nstat_ifnet_report_lim_stats(void);
static void         nstat_net_api_report_stats(void);
static errno_t      nstat_set_provider_filter( nstat_control_state  *state, nstat_msg_add_all_srcs *req);
static errno_t nstat_control_send_event(nstat_control_state *state, nstat_src *src, u_int64_t event);

static u_int32_t    nstat_udp_watchers = 0;
static u_int32_t    nstat_tcp_watchers = 0;
static nstat_merged_provider_filters merged_filters = {};

static void nstat_control_register(void);

/*
 * The lock order is as follows:
 *
 * socket_lock (inpcb)
 *     nstat_mtx
 *         state->ncs_mtx
 */
static nstat_control_state      *nstat_controls = NULL;
static uint64_t                  nstat_idle_time = 0;
static LCK_GRP_DECLARE(nstat_lck_grp, "network statistics kctl");
static LCK_MTX_DECLARE(nstat_mtx, &nstat_lck_grp);


/* some extern definitions */
extern void mbuf_report_peak_usage(void);
extern void tcp_report_stats(void);

static void
nstat_copy_sa_out(
	const struct sockaddr   *src,
	struct sockaddr                 *dst,
	int                                             maxlen)
{
	if (src->sa_len > maxlen) {
		return;
	}

	bcopy(src, dst, src->sa_len);
	if (src->sa_family == AF_INET6 &&
	    src->sa_len >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6     *sin6 = (struct sockaddr_in6*)(void *)dst;
		if (IN6_IS_SCOPE_EMBED(&sin6->sin6_addr)) {
			sin6->sin6_scope_id = ((const struct sockaddr_in6*)(const void*)(src))->sin6_scope_id;
			if (in6_embedded_scope) {
				in6_verify_ifscope(&sin6->sin6_addr, sin6->sin6_scope_id);
				sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
				sin6->sin6_addr.s6_addr16[1] = 0;
			}
		}
	}
}

static void
nstat_ip_to_sockaddr(
	const struct in_addr    *ip,
	u_int16_t               port,
	struct sockaddr_in      *sin,
	u_int32_t               maxlen)
{
	if (maxlen < sizeof(struct sockaddr_in)) {
		return;
	}

	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	sin->sin_port = port;
	sin->sin_addr = *ip;
}

u_int16_t
nstat_ifnet_to_flags(
	struct ifnet *ifp)
{
	u_int16_t flags = 0;
	u_int32_t functional_type = if_functional_type(ifp, FALSE);

	/* Panic if someone adds a functional type without updating ntstat. */
	VERIFY(0 <= functional_type && functional_type <= IFRTYPE_FUNCTIONAL_LAST);

	switch (functional_type) {
	case IFRTYPE_FUNCTIONAL_UNKNOWN:
		flags |= NSTAT_IFNET_IS_UNKNOWN_TYPE;
		break;
	case IFRTYPE_FUNCTIONAL_LOOPBACK:
		flags |= NSTAT_IFNET_IS_LOOPBACK;
		break;
	case IFRTYPE_FUNCTIONAL_WIRED:
	case IFRTYPE_FUNCTIONAL_INTCOPROC:
	case IFRTYPE_FUNCTIONAL_MANAGEMENT:
		flags |= NSTAT_IFNET_IS_WIRED;
		break;
	case IFRTYPE_FUNCTIONAL_WIFI_INFRA:
		flags |= NSTAT_IFNET_IS_WIFI;
		break;
	case IFRTYPE_FUNCTIONAL_WIFI_AWDL:
		flags |= NSTAT_IFNET_IS_WIFI;
		flags |= NSTAT_IFNET_IS_AWDL;
		break;
	case IFRTYPE_FUNCTIONAL_CELLULAR:
		flags |= NSTAT_IFNET_IS_CELLULAR;
		break;
	case IFRTYPE_FUNCTIONAL_COMPANIONLINK:
		flags |= NSTAT_IFNET_IS_COMPANIONLINK;
		break;
	}

	if (IFNET_IS_EXPENSIVE(ifp)) {
		flags |= NSTAT_IFNET_IS_EXPENSIVE;
	}
	if (IFNET_IS_CONSTRAINED(ifp)) {
		flags |= NSTAT_IFNET_IS_CONSTRAINED;
	}
	if (ifp->if_xflags & IFXF_LOW_LATENCY) {
		flags |= NSTAT_IFNET_IS_WIFI;
		flags |= NSTAT_IFNET_IS_LLW;
	}

	return flags;
}

static u_int32_t
extend_ifnet_flags(
	u_int16_t condensed_flags)
{
	u_int32_t extended_flags = (u_int32_t)condensed_flags;

	if ((extended_flags & NSTAT_IFNET_IS_WIFI) && ((extended_flags & (NSTAT_IFNET_IS_AWDL | NSTAT_IFNET_IS_LLW)) == 0)) {
		extended_flags |= NSTAT_IFNET_IS_WIFI_INFRA;
	}
	return extended_flags;
}

u_int32_t
nstat_ifnet_to_flags_extended(
	struct ifnet *ifp)
{
	u_int32_t flags = extend_ifnet_flags(nstat_ifnet_to_flags(ifp));

	return flags;
}

static void
nstat_update_local_flag_from_inpcb_route(const struct inpcb *inp,
    u_int32_t *flags)
{
	if (inp != NULL &&
	    ((inp->inp_route.ro_rt != NULL &&
	    IS_LOCALNET_ROUTE(inp->inp_route.ro_rt)) ||
	    (inp->inp_flags2 & INP2_LAST_ROUTE_LOCAL))) {
		*flags |= NSTAT_IFNET_IS_LOCAL;
	} else {
		*flags |= NSTAT_IFNET_IS_NON_LOCAL;
	}
}

static u_int32_t
nstat_inpcb_to_flags(
	const struct inpcb *inp)
{
	u_int32_t flags = 0;

	if (inp != NULL) {
		if (inp->inp_last_outifp != NULL) {
			struct ifnet *ifp = inp->inp_last_outifp;
			flags = nstat_ifnet_to_flags_extended(ifp);

			struct tcpcb  *tp = intotcpcb(inp);
			if (tp) {
				if (tp->t_flags & TF_LOCAL) {
					flags |= NSTAT_IFNET_IS_LOCAL;
				} else {
					flags |= NSTAT_IFNET_IS_NON_LOCAL;
				}
			} else {
				nstat_update_local_flag_from_inpcb_route(inp, &flags);
			}
		} else {
			flags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
			nstat_update_local_flag_from_inpcb_route(inp, &flags);
		}
		if (inp->inp_socket != NULL &&
		    (inp->inp_socket->so_flags1 & SOF1_CELLFALLBACK)) {
			flags |= NSTAT_IFNET_VIA_CELLFALLBACK;
		}
	}
	return flags;
}

static void
merge_current_event_filters(void)
{
	// The nstat_mtx is assumed locked
	nstat_merged_provider_filters new_merge = {};
	nstat_provider_type_t provider;
	nstat_control_state *state;

	for (state = nstat_controls; state; state = state->ncs_next) {
		for (provider = NSTAT_PROVIDER_NONE; provider <= NSTAT_PROVIDER_LAST; provider++) {
			new_merge.mpf_filters[provider].mf_events |= state->ncs_provider_filters[provider].npf_events;
		}
	}
	for (provider = NSTAT_PROVIDER_NONE; provider <= NSTAT_PROVIDER_LAST; provider++) {
		// This should do atomic updates of the 64 bit words, where memcpy would be undefined
		merged_filters.mpf_filters[provider].mf_events = new_merge.mpf_filters[provider].mf_events;
	}
}


#pragma mark -- Network Statistic Providers --

static errno_t nstat_control_source_add(u_int64_t context, nstat_control_state *state, nstat_provider *provider, nstat_provider_cookie_t cookie);
struct nstat_provider   *nstat_providers = NULL;

static struct nstat_provider*
nstat_find_provider_by_id(
	nstat_provider_id_t     id)
{
	struct nstat_provider   *provider;

	for (provider = nstat_providers; provider != NULL; provider = provider->next) {
		if (provider->nstat_provider_id == id) {
			break;
		}
	}

	return provider;
}

static errno_t
nstat_lookup_entry(
	nstat_provider_id_t     id,
	const void              *data,
	u_int32_t               length,
	nstat_provider          **out_provider,
	nstat_provider_cookie_t *out_cookie)
{
	*out_provider = nstat_find_provider_by_id(id);
	if (*out_provider == NULL) {
		return ENOENT;
	}

	return (*out_provider)->nstat_lookup(data, length, out_cookie);
}

static void
nstat_control_sanitize_cookie(
	nstat_control_state     *state,
	nstat_provider_id_t     id,
	nstat_provider_cookie_t cookie)
{
	nstat_src *src = NULL;

	// Scan the source list to find any duplicate entry and remove it.
	lck_mtx_lock(&state->ncs_mtx);
	TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
	{
		nstat_provider *sp = src->provider;
		if (sp->nstat_provider_id == id &&
		    sp->nstat_cookie_equal != NULL &&
		    sp->nstat_cookie_equal(src->cookie, cookie)) {
			break;
		}
	}
	if (src) {
		nstat_control_send_goodbye(state, src);
		TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
	}
	lck_mtx_unlock(&state->ncs_mtx);

	if (src) {
		nstat_control_cleanup_source(NULL, src, TRUE);
	}
}

static void nstat_init_route_provider(void);
static void nstat_init_tcp_provider(void);
static void nstat_init_udp_provider(void);
#if SKYWALK
static void nstat_init_userland_tcp_provider(void);
static void nstat_init_userland_udp_provider(void);
static void nstat_init_userland_quic_provider(void);
#endif /* SKYWALK */
static void nstat_init_userland_conn_provider(void);
static void nstat_init_udp_subflow_provider(void);
static void nstat_init_ifnet_provider(void);

__private_extern__ void
nstat_init(void)
{
	nstat_init_route_provider();
	nstat_init_tcp_provider();
	nstat_init_udp_provider();
#if SKYWALK
	nstat_init_userland_tcp_provider();
	nstat_init_userland_udp_provider();
	nstat_init_userland_quic_provider();
#endif /* SKYWALK */
	nstat_init_userland_conn_provider();
	nstat_init_udp_subflow_provider();
	nstat_init_ifnet_provider();
	nstat_control_register();
}

#pragma mark -- Aligned Buffer Allocation --

struct align_header {
	u_int32_t       offset;
	u_int32_t       length;
};

static void*
nstat_malloc_aligned(
	size_t          length,
	u_int8_t        alignment,
	zalloc_flags_t  flags)
{
	struct align_header     *hdr = NULL;
	size_t size = length + sizeof(*hdr) + alignment - 1;

	// Arbitrary limit to prevent abuse
	if (length > (64 * 1024)) {
		return NULL;
	}
	u_int8_t *buffer = (u_int8_t *)kalloc_data(size, flags);
	if (buffer == NULL) {
		return NULL;
	}

	u_int8_t *aligned = buffer + sizeof(*hdr);
	aligned = (u_int8_t*)P2ROUNDUP(aligned, alignment);

	hdr = (struct align_header*)(void *)(aligned - sizeof(*hdr));
	hdr->offset = aligned - buffer;
	hdr->length = size;

	return aligned;
}

static void
nstat_free_aligned(
	void            *buffer)
{
	struct align_header *hdr = (struct align_header*)(void *)((u_int8_t*)buffer - sizeof(*hdr));
	char *offset_buffer = (char *)buffer - hdr->offset;
	kfree_data(offset_buffer, hdr->length);
}

#pragma mark -- Utilities --

#define NSTAT_PROCDETAILS_MAGIC     0xfeedc001
#define NSTAT_PROCDETAILS_UNMAGIC   0xdeadc001

static tailq_head_procdetails nstat_procdetails_head = TAILQ_HEAD_INITIALIZER(nstat_procdetails_head);

static struct nstat_procdetails *
nstat_retain_curprocdetails(void)
{
	struct nstat_procdetails *procdetails = NULL;
	uint64_t upid = proc_uniqueid(current_proc());

	lck_mtx_lock(&nstat_mtx);

	TAILQ_FOREACH(procdetails, &nstat_procdetails_head, pdet_link) {
		assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

		if (procdetails->pdet_upid == upid) {
			OSIncrementAtomic(&procdetails->pdet_refcnt);
			break;
		}
	}
	lck_mtx_unlock(&nstat_mtx);
	if (!procdetails) {
		// No need for paranoia on locking, it would be OK if there are duplicate structs on the list
		procdetails = kalloc_type(struct nstat_procdetails,
		    Z_WAITOK | Z_NOFAIL);
		procdetails->pdet_pid = proc_selfpid();
		procdetails->pdet_upid = upid;
		proc_selfname(procdetails->pdet_procname, sizeof(procdetails->pdet_procname));
		proc_getexecutableuuid(current_proc(), procdetails->pdet_uuid, sizeof(uuid_t));
		procdetails->pdet_refcnt = 1;
		procdetails->pdet_magic = NSTAT_PROCDETAILS_MAGIC;
		lck_mtx_lock(&nstat_mtx);
		TAILQ_INSERT_HEAD(&nstat_procdetails_head, procdetails, pdet_link);
		lck_mtx_unlock(&nstat_mtx);
	}

	return procdetails;
}

static void
nstat_release_procdetails(struct nstat_procdetails *procdetails)
{
	assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);
	// These are harvested later to amortize costs
	OSDecrementAtomic(&procdetails->pdet_refcnt);
}

static void
nstat_prune_procdetails(void)
{
	struct nstat_procdetails *procdetails;
	struct nstat_procdetails *tmpdetails;
	tailq_head_procdetails dead_list;

	TAILQ_INIT(&dead_list);
	lck_mtx_lock(&nstat_mtx);

	TAILQ_FOREACH_SAFE(procdetails, &nstat_procdetails_head, pdet_link, tmpdetails)
	{
		assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);
		if (procdetails->pdet_refcnt == 0) {
			// Pull it off the list
			TAILQ_REMOVE(&nstat_procdetails_head, procdetails, pdet_link);
			TAILQ_INSERT_TAIL(&dead_list, procdetails, pdet_link);
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	while ((procdetails = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, procdetails, pdet_link);
		procdetails->pdet_magic = NSTAT_PROCDETAILS_UNMAGIC;
		kfree_type(struct nstat_procdetails, procdetails);
	}
}

#pragma mark -- Route Provider --

static nstat_provider   nstat_route_provider;

static errno_t
nstat_route_lookup(
	const void      *data,
	u_int32_t       length,
	nstat_provider_cookie_t *out_cookie)
{
	// rt_lookup doesn't take const params but it doesn't modify the parameters for
	// the lookup. So...we use a union to eliminate the warning.
	union{
		struct sockaddr *sa;
		const struct sockaddr *const_sa;
	} dst, mask;

	const nstat_route_add_param     *param = (const nstat_route_add_param*)data;
	*out_cookie = NULL;

	if (length < sizeof(*param)) {
		return EINVAL;
	}

	if (param->dst.v4.sin_family == 0 ||
	    param->dst.v4.sin_family > AF_MAX ||
	    (param->mask.v4.sin_family != 0 && param->mask.v4.sin_family != param->dst.v4.sin_family)) {
		return EINVAL;
	}

	if (param->dst.v4.sin_len > sizeof(param->dst) ||
	    (param->mask.v4.sin_family && param->mask.v4.sin_len > sizeof(param->mask.v4.sin_len))) {
		return EINVAL;
	}
	if ((param->dst.v4.sin_family == AF_INET &&
	    param->dst.v4.sin_len < sizeof(struct sockaddr_in)) ||
	    (param->dst.v6.sin6_family == AF_INET6 &&
	    param->dst.v6.sin6_len < sizeof(struct sockaddr_in6))) {
		return EINVAL;
	}

	dst.const_sa = (const struct sockaddr*)&param->dst;
	mask.const_sa = param->mask.v4.sin_family ? (const struct sockaddr*)&param->mask : NULL;

	struct radix_node_head  *rnh = rt_tables[dst.sa->sa_family];
	if (rnh == NULL) {
		return EAFNOSUPPORT;
	}

	lck_mtx_lock(rnh_lock);
	struct rtentry *rt = rt_lookup(TRUE, dst.sa, mask.sa, rnh, param->ifindex);
	lck_mtx_unlock(rnh_lock);

	if (rt) {
		*out_cookie = (nstat_provider_cookie_t)rt;
	}

	return rt ? 0 : ENOENT;
}

static int
nstat_route_gone(
	nstat_provider_cookie_t cookie)
{
	struct rtentry          *rt = (struct rtentry*)cookie;
	return ((rt->rt_flags & RTF_UP) == 0) ? 1 : 0;
}

static errno_t
nstat_route_counts(
	nstat_provider_cookie_t cookie,
	struct nstat_counts     *out_counts,
	int                     *out_gone)
{
	struct rtentry          *rt = (struct rtentry*)cookie;
	struct nstat_counts     *rt_stats = rt->rt_stats;

	if (out_gone) {
		*out_gone = 0;
	}

	if (out_gone && (rt->rt_flags & RTF_UP) == 0) {
		*out_gone = 1;
	}

	if (rt_stats) {
		out_counts->nstat_rxpackets = os_atomic_load(&rt_stats->nstat_rxpackets, relaxed);
		out_counts->nstat_rxbytes = os_atomic_load(&rt_stats->nstat_rxbytes, relaxed);
		out_counts->nstat_txpackets = os_atomic_load(&rt_stats->nstat_txpackets, relaxed);
		out_counts->nstat_txbytes = os_atomic_load(&rt_stats->nstat_txbytes, relaxed);
		out_counts->nstat_rxduplicatebytes = rt_stats->nstat_rxduplicatebytes;
		out_counts->nstat_rxoutoforderbytes = rt_stats->nstat_rxoutoforderbytes;
		out_counts->nstat_txretransmit = rt_stats->nstat_txretransmit;
		out_counts->nstat_connectattempts = rt_stats->nstat_connectattempts;
		out_counts->nstat_connectsuccesses = rt_stats->nstat_connectsuccesses;
		out_counts->nstat_min_rtt = rt_stats->nstat_min_rtt;
		out_counts->nstat_avg_rtt = rt_stats->nstat_avg_rtt;
		out_counts->nstat_var_rtt = rt_stats->nstat_var_rtt;
		out_counts->nstat_cell_rxbytes = out_counts->nstat_cell_txbytes = 0;
	} else {
		bzero(out_counts, sizeof(*out_counts));
	}

	return 0;
}

static void
nstat_route_release(
	nstat_provider_cookie_t cookie,
	__unused int locked)
{
	rtfree((struct rtentry*)cookie);
}

static u_int32_t    nstat_route_watchers = 0;

static int
nstat_route_walktree_add(
	struct radix_node       *rn,
	void                            *context)
{
	errno_t result = 0;
	struct rtentry *rt = (struct rtentry *)rn;
	nstat_control_state     *state  = (nstat_control_state*)context;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	/* RTF_UP can't change while rnh_lock is held */
	if ((rt->rt_flags & RTF_UP) != 0) {
		/* Clear RTPRF_OURS if the route is still usable */
		RT_LOCK(rt);
		if (rt_validate(rt)) {
			RT_ADDREF_LOCKED(rt);
			RT_UNLOCK(rt);
		} else {
			RT_UNLOCK(rt);
			rt = NULL;
		}

		/* Otherwise if RTF_CONDEMNED, treat it as if it were down */
		if (rt == NULL) {
			return 0;
		}

		result = nstat_control_source_add(0, state, &nstat_route_provider, rt);
		if (result != 0) {
			rtfree_locked(rt);
		}
	}

	return result;
}

static errno_t
nstat_route_add_watcher(
	nstat_control_state *state,
	nstat_msg_add_all_srcs *req)
{
	int i;
	errno_t result = 0;

	lck_mtx_lock(rnh_lock);

	result = nstat_set_provider_filter(state, req);
	if (result == 0) {
		OSIncrementAtomic(&nstat_route_watchers);

		for (i = 1; i < AF_MAX; i++) {
			struct radix_node_head *rnh;
			rnh = rt_tables[i];
			if (!rnh) {
				continue;
			}

			result = rnh->rnh_walktree(rnh, nstat_route_walktree_add, state);
			if (result != 0) {
				// This is probably resource exhaustion.
				// There currently isn't a good way to recover from this.
				// Least bad seems to be to give up on the add-all but leave
				// the watcher in place.
				break;
			}
		}
	}
	lck_mtx_unlock(rnh_lock);

	return result;
}

__private_extern__ void
nstat_route_new_entry(
	struct rtentry  *rt)
{
	if (nstat_route_watchers == 0) {
		return;
	}

	lck_mtx_lock(&nstat_mtx);
	if ((rt->rt_flags & RTF_UP) != 0) {
		nstat_control_state     *state;
		for (state = nstat_controls; state; state = state->ncs_next) {
			if ((state->ncs_watching & (1 << NSTAT_PROVIDER_ROUTE)) != 0) {
				// this client is watching routes
				// acquire a reference for the route
				RT_ADDREF(rt);

				// add the source, if that fails, release the reference
				if (nstat_control_source_add(0, state, &nstat_route_provider, rt) != 0) {
					RT_REMREF(rt);
				}
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
}

static void
nstat_route_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_route_watchers);
}

static errno_t
nstat_route_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *data,
	size_t                  len)
{
	nstat_route_descriptor  *desc = (nstat_route_descriptor*)data;
	if (len < sizeof(*desc)) {
		return EINVAL;
	}
	bzero(desc, sizeof(*desc));

	struct rtentry  *rt = (struct rtentry*)cookie;
	desc->id = (uint64_t)VM_KERNEL_ADDRPERM(rt);
	desc->parent_id = (uint64_t)VM_KERNEL_ADDRPERM(rt->rt_parent);
	desc->gateway_id = (uint64_t)VM_KERNEL_ADDRPERM(rt->rt_gwroute);


	// key/dest
	struct sockaddr *sa;
	if ((sa = rt_key(rt))) {
		nstat_copy_sa_out(sa, &desc->dst.sa, sizeof(desc->dst));
	}

	// mask
	if ((sa = rt_mask(rt)) && sa->sa_len <= sizeof(desc->mask)) {
		memcpy(&desc->mask, sa, sa->sa_len);
	}

	// gateway
	if ((sa = rt->rt_gateway)) {
		nstat_copy_sa_out(sa, &desc->gateway.sa, sizeof(desc->gateway));
	}

	if (rt->rt_ifp) {
		desc->ifindex = rt->rt_ifp->if_index;
	}

	desc->flags = rt->rt_flags;

	return 0;
}

static bool
nstat_route_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	__unused u_int64_t suppression_flags)
{
	bool retval = true;

	if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0) {
		struct rtentry  *rt = (struct rtentry*)cookie;
		struct ifnet *ifp = rt->rt_ifp;

		if (ifp) {
			uint32_t interface_properties = nstat_ifnet_to_flags_extended(ifp);

			if ((filter->npf_flags & interface_properties) == 0) {
				retval = false;
			}
		}
	}
	return retval;
}

static bool
nstat_route_cookie_equal(
	nstat_provider_cookie_t cookie1,
	nstat_provider_cookie_t cookie2)
{
	struct rtentry *rt1 = (struct rtentry *)cookie1;
	struct rtentry *rt2 = (struct rtentry *)cookie2;

	return (rt1 == rt2) ? true : false;
}

static void
nstat_init_route_provider(void)
{
	bzero(&nstat_route_provider, sizeof(nstat_route_provider));
	nstat_route_provider.nstat_descriptor_length = sizeof(nstat_route_descriptor);
	nstat_route_provider.nstat_provider_id = NSTAT_PROVIDER_ROUTE;
	nstat_route_provider.nstat_lookup = nstat_route_lookup;
	nstat_route_provider.nstat_gone = nstat_route_gone;
	nstat_route_provider.nstat_counts = nstat_route_counts;
	nstat_route_provider.nstat_release = nstat_route_release;
	nstat_route_provider.nstat_watcher_add = nstat_route_add_watcher;
	nstat_route_provider.nstat_watcher_remove = nstat_route_remove_watcher;
	nstat_route_provider.nstat_copy_descriptor = nstat_route_copy_descriptor;
	nstat_route_provider.nstat_reporting_allowed = nstat_route_reporting_allowed;
	nstat_route_provider.nstat_cookie_equal = nstat_route_cookie_equal;
	nstat_route_provider.next = nstat_providers;
	nstat_providers = &nstat_route_provider;
}

#pragma mark -- Route Collection --

__private_extern__ struct nstat_counts*
nstat_route_attach(
	struct rtentry  *rte)
{
	struct nstat_counts *result = rte->rt_stats;
	if (result) {
		return result;
	}

	result = nstat_malloc_aligned(sizeof(*result), sizeof(u_int64_t),
	    Z_WAITOK | Z_ZERO);
	if (!result) {
		return result;
	}

	if (!OSCompareAndSwapPtr(NULL, result, &rte->rt_stats)) {
		nstat_free_aligned(result);
		result = rte->rt_stats;
	}

	return result;
}

__private_extern__ void
nstat_route_detach(
	struct rtentry  *rte)
{
	if (rte->rt_stats) {
		nstat_free_aligned(rte->rt_stats);
		rte->rt_stats = NULL;
	}
}

__private_extern__ void
nstat_route_connect_attempt(
	struct rtentry  *rte)
{
	while (rte) {
		struct nstat_counts*    stats = nstat_route_attach(rte);
		if (stats) {
			OSIncrementAtomic(&stats->nstat_connectattempts);
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_connect_success(
	struct rtentry  *rte)
{
	// This route
	while (rte) {
		struct nstat_counts*    stats = nstat_route_attach(rte);
		if (stats) {
			OSIncrementAtomic(&stats->nstat_connectsuccesses);
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_tx(
	struct rtentry  *rte,
	u_int32_t       packets,
	u_int32_t       bytes,
	u_int32_t       flags)
{
	while (rte) {
		struct nstat_counts*    stats = nstat_route_attach(rte);
		if (stats) {
			if ((flags & NSTAT_TX_FLAG_RETRANSMIT) != 0) {
				OSAddAtomic(bytes, &stats->nstat_txretransmit);
			} else {
				OSAddAtomic64((SInt64)packets, (SInt64*)&stats->nstat_txpackets);
				OSAddAtomic64((SInt64)bytes, (SInt64*)&stats->nstat_txbytes);
			}
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_rx(
	struct rtentry  *rte,
	u_int32_t       packets,
	u_int32_t       bytes,
	u_int32_t       flags)
{
	while (rte) {
		struct nstat_counts*    stats = nstat_route_attach(rte);
		if (stats) {
			if (flags == 0) {
				OSAddAtomic64((SInt64)packets, (SInt64*)&stats->nstat_rxpackets);
				OSAddAtomic64((SInt64)bytes, (SInt64*)&stats->nstat_rxbytes);
			} else {
				if (flags & NSTAT_RX_FLAG_OUT_OF_ORDER) {
					OSAddAtomic(bytes, &stats->nstat_rxoutoforderbytes);
				}
				if (flags & NSTAT_RX_FLAG_DUPLICATE) {
					OSAddAtomic(bytes, &stats->nstat_rxduplicatebytes);
				}
			}
		}

		rte = rte->rt_parent;
	}
}

/* atomically average current value at _val_addr with _new_val and store  */
#define NSTAT_EWMA_ATOMIC(_val_addr, _new_val, _decay) do {                                     \
	volatile uint32_t _old_val;                                                                                             \
	volatile uint32_t _avg;                                                                                                 \
	do {                                                                                                                                    \
	        _old_val = *_val_addr;                                                                                          \
	        if (_old_val == 0)                                                                                                      \
	        {                                                                                                                                       \
	                _avg = _new_val;                                                                                                \
	        }                                                                                                                                       \
	        else                                                                                                                            \
	        {                                                                                                                                       \
	                _avg = _old_val - (_old_val >> _decay) + (_new_val >> _decay);  \
	        }                                                                                                                                       \
	        if (_old_val == _avg) break;                                                                            \
	} while (!OSCompareAndSwap(_old_val, _avg, _val_addr));                                 \
} while (0);

/* atomically compute minimum of current value at _val_addr with _new_val and store  */
#define NSTAT_MIN_ATOMIC(_val_addr, _new_val) do {                              \
	volatile uint32_t _old_val;                                                                     \
	do {                                                                                                            \
	        _old_val = *_val_addr;                                                                  \
	        if (_old_val != 0 && _old_val < _new_val)                               \
	        {                                                                                                               \
	                break;                                                                                          \
	        }                                                                                                               \
	} while (!OSCompareAndSwap(_old_val, _new_val, _val_addr));     \
} while (0);

__private_extern__ void
nstat_route_rtt(
	struct rtentry  *rte,
	u_int32_t               rtt,
	u_int32_t               rtt_var)
{
	const uint32_t decay = 3;

	while (rte) {
		struct nstat_counts*    stats = nstat_route_attach(rte);
		if (stats) {
			NSTAT_EWMA_ATOMIC(&stats->nstat_avg_rtt, rtt, decay);
			NSTAT_MIN_ATOMIC(&stats->nstat_min_rtt, rtt);
			NSTAT_EWMA_ATOMIC(&stats->nstat_var_rtt, rtt_var, decay);
		}
		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_update(
	struct rtentry  *rte,
	uint32_t        connect_attempts,
	uint32_t        connect_successes,
	uint32_t        rx_packets,
	uint32_t        rx_bytes,
	uint32_t        rx_duplicatebytes,
	uint32_t        rx_outoforderbytes,
	uint32_t        tx_packets,
	uint32_t        tx_bytes,
	uint32_t        tx_retransmit,
	uint32_t        rtt,
	uint32_t        rtt_var)
{
	const uint32_t decay = 3;

	while (rte) {
		struct nstat_counts*    stats = nstat_route_attach(rte);
		if (stats) {
			OSAddAtomic(connect_attempts, &stats->nstat_connectattempts);
			OSAddAtomic(connect_successes, &stats->nstat_connectsuccesses);
			OSAddAtomic64((SInt64)tx_packets, (SInt64*)&stats->nstat_txpackets);
			OSAddAtomic64((SInt64)tx_bytes, (SInt64*)&stats->nstat_txbytes);
			OSAddAtomic(tx_retransmit, &stats->nstat_txretransmit);
			OSAddAtomic64((SInt64)rx_packets, (SInt64*)&stats->nstat_rxpackets);
			OSAddAtomic64((SInt64)rx_bytes, (SInt64*)&stats->nstat_rxbytes);
			OSAddAtomic(rx_outoforderbytes, &stats->nstat_rxoutoforderbytes);
			OSAddAtomic(rx_duplicatebytes, &stats->nstat_rxduplicatebytes);

			if (rtt != 0) {
				NSTAT_EWMA_ATOMIC(&stats->nstat_avg_rtt, rtt, decay);
				NSTAT_MIN_ATOMIC(&stats->nstat_min_rtt, rtt);
				NSTAT_EWMA_ATOMIC(&stats->nstat_var_rtt, rtt_var, decay);
			}
		}
		rte = rte->rt_parent;
	}
}

#pragma mark -- TCP Kernel Provider --

/*
 * Due to the way the kernel deallocates a process (the process structure
 * might be gone by the time we get the PCB detach notification),
 * we need to cache the process name. Without this, proc_name() would
 * return null and the process name would never be sent to userland.
 *
 * For UDP sockets, we also store the cached the connection tuples along with
 * the interface index. This is necessary because when UDP sockets are
 * disconnected, the connection tuples are forever lost from the inpcb, thus
 * we need to keep track of the last call to connect() in ntstat.
 */
struct nstat_tucookie {
	struct inpcb    *inp;
	char            pname[MAXCOMLEN + 1];
	bool            cached;
	union{
		struct sockaddr_in      v4;
		struct sockaddr_in6     v6;
	} local;
	union{
		struct sockaddr_in      v4;
		struct sockaddr_in6     v6;
	} remote;
	unsigned int    if_index;
	uint32_t        ifnet_properties;
};

static struct nstat_tucookie *
nstat_tucookie_alloc_internal(
	struct inpcb *inp,
	bool          ref,
	bool          locked)
{
	struct nstat_tucookie *cookie;

	cookie = kalloc_type(struct nstat_tucookie,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	if (!locked) {
		LCK_MTX_ASSERT(&nstat_mtx, LCK_MTX_ASSERT_NOTOWNED);
	}
	if (ref && in_pcb_checkstate(inp, WNT_ACQUIRE, locked) == WNT_STOPUSING) {
		kfree_type(struct nstat_tucookie, cookie);
		return NULL;
	}
	cookie->inp = inp;
	proc_name(inp->inp_socket->last_pid, cookie->pname,
	    sizeof(cookie->pname));
	/*
	 * We only increment the reference count for UDP sockets because we
	 * only cache UDP socket tuples.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP) {
		OSIncrementAtomic(&inp->inp_nstat_refcnt);
	}

	return cookie;
}

__unused static struct nstat_tucookie *
nstat_tucookie_alloc(
	struct inpcb *inp)
{
	return nstat_tucookie_alloc_internal(inp, false, false);
}

static struct nstat_tucookie *
nstat_tucookie_alloc_ref(
	struct inpcb *inp)
{
	return nstat_tucookie_alloc_internal(inp, true, false);
}

static struct nstat_tucookie *
nstat_tucookie_alloc_ref_locked(
	struct inpcb *inp)
{
	return nstat_tucookie_alloc_internal(inp, true, true);
}

static void
nstat_tucookie_release_internal(
	struct nstat_tucookie *cookie,
	int                         inplock)
{
	if (SOCK_PROTO(cookie->inp->inp_socket) == IPPROTO_UDP) {
		OSDecrementAtomic(&cookie->inp->inp_nstat_refcnt);
	}
	in_pcb_checkstate(cookie->inp, WNT_RELEASE, inplock);
	kfree_type(struct nstat_tucookie, cookie);
}

static void
nstat_tucookie_release(
	struct nstat_tucookie *cookie)
{
	nstat_tucookie_release_internal(cookie, false);
}

static void
nstat_tucookie_release_locked(
	struct nstat_tucookie *cookie)
{
	nstat_tucookie_release_internal(cookie, true);
}


static size_t
nstat_inp_domain_info(struct inpcb *inp, nstat_domain_info *domain_info, size_t len)
{
	// Note, the caller has guaranteed that the buffer has been zeroed, there is no need to clear it again
	struct socket         *so = inp->inp_socket;

	if (so == NULL) {
		return 0;
	}

	NSTAT_DEBUG_SOCKET_LOG(so, "NSTAT: Collecting stats");

	if (domain_info == NULL) {
		return sizeof(nstat_domain_info);
	}

	if (len < sizeof(nstat_domain_info)) {
		return 0;
	}

	necp_copy_inp_domain_info(inp, so, domain_info);

	NSTAT_DEBUG_SOCKET_LOG(so, "NSTAT: <pid %d> Collected stats - domain <%s> owner <%s> ctxt <%s> bundle id <%s> "
	    "is_tracker %d is_non_app_initiated %d is_silent %d",
	    so->so_flags & SOF_DELEGATED ? so->e_pid : so->last_pid,
	    domain_info->domain_name,
	    domain_info->domain_owner,
	    domain_info->domain_tracker_ctxt,
	    domain_info->domain_attributed_bundle_id,
	    domain_info->is_tracker,
	    domain_info->is_non_app_initiated,
	    domain_info->is_silent);

	return sizeof(nstat_domain_info);
}


static nstat_provider   nstat_tcp_provider;

static errno_t
nstat_tcp_lookup(
	__unused const void              *data,
	__unused u_int32_t               length,
	__unused nstat_provider_cookie_t *out_cookie)
{
	// Looking up a specific connection is not supported.
	return ENOTSUP;
}

static int
nstat_tcp_gone(
	nstat_provider_cookie_t cookie)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb *inp;
	struct tcpcb *tp;

	return (!(inp = tucookie->inp) ||
	       !(tp = intotcpcb(inp)) ||
	       inp->inp_state == INPCB_STATE_DEAD) ? 1 : 0;
}

static errno_t
nstat_tcp_counts(
	nstat_provider_cookie_t cookie,
	struct nstat_counts     *out_counts,
	int                     *out_gone)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb *inp;

	bzero(out_counts, sizeof(*out_counts));

	if (out_gone) {
		*out_gone = 0;
	}

	// if the pcb is in the dead state, we should stop using it
	if (nstat_tcp_gone(cookie)) {
		if (out_gone) {
			*out_gone = 1;
		}
		if (!(inp = tucookie->inp) || !intotcpcb(inp)) {
			return EINVAL;
		}
	}
	inp = tucookie->inp;
	struct tcpcb *tp = intotcpcb(inp);

	out_counts->nstat_rxpackets = os_atomic_load(&inp->inp_stat->rxpackets, relaxed);
	out_counts->nstat_rxbytes = os_atomic_load(&inp->inp_stat->rxbytes, relaxed);
	out_counts->nstat_txpackets = os_atomic_load(&inp->inp_stat->txpackets, relaxed);
	out_counts->nstat_txbytes = os_atomic_load(&inp->inp_stat->txbytes, relaxed);
	out_counts->nstat_rxduplicatebytes = tp->t_stat.rxduplicatebytes;
	out_counts->nstat_rxoutoforderbytes = tp->t_stat.rxoutoforderbytes;
	out_counts->nstat_txretransmit = tp->t_stat.txretransmitbytes;
	out_counts->nstat_connectattempts = tp->t_state >= TCPS_SYN_SENT ? 1 : 0;
	out_counts->nstat_connectsuccesses = tp->t_state >= TCPS_ESTABLISHED ? 1 : 0;
	out_counts->nstat_avg_rtt = tp->t_srtt;
	out_counts->nstat_min_rtt = tp->t_rttbest;
	out_counts->nstat_var_rtt = tp->t_rttvar;
	if (out_counts->nstat_avg_rtt < out_counts->nstat_min_rtt) {
		out_counts->nstat_min_rtt = out_counts->nstat_avg_rtt;
	}
	out_counts->nstat_cell_rxbytes = os_atomic_load(&inp->inp_cstat->rxbytes, relaxed);
	out_counts->nstat_cell_txbytes = os_atomic_load(&inp->inp_cstat->txbytes, relaxed);
	out_counts->nstat_wifi_rxbytes = os_atomic_load(&inp->inp_wstat->rxbytes, relaxed);
	out_counts->nstat_wifi_txbytes = os_atomic_load(&inp->inp_wstat->txbytes, relaxed);
	out_counts->nstat_wired_rxbytes = os_atomic_load(&inp->inp_Wstat->rxbytes, relaxed);
	out_counts->nstat_wired_txbytes = os_atomic_load(&inp->inp_Wstat->txbytes, relaxed);

	return 0;
}

static void
nstat_tcp_release(
	nstat_provider_cookie_t cookie,
	int locked)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;

	nstat_tucookie_release_internal(tucookie, locked);
}

static errno_t
nstat_tcp_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs  *req)
{
	// There is a tricky issue around getting all TCP sockets added once
	// and only once.  nstat_tcp_new_pcb() is called prior to the new item
	// being placed on any lists where it might be found.
	// By locking the tcbinfo.ipi_lock prior to marking the state as a watcher,
	// it should be impossible for a new socket to be added twice.
	// On the other hand, there is still a timing issue where a new socket
	// results in a call to nstat_tcp_new_pcb() before this watcher
	// is instantiated and yet the socket doesn't make it into ipi_listhead
	// prior to the scan.  <rdar://problem/30361716>

	errno_t result;

	lck_rw_lock_shared(&tcbinfo.ipi_lock);
	result = nstat_set_provider_filter(state, req);
	if (result == 0) {
		OSIncrementAtomic(&nstat_tcp_watchers);

		// Add all current tcp inpcbs. Ignore those in timewait
		struct inpcb *inp;
		struct nstat_tucookie *cookie;
		LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list)
		{
			cookie = nstat_tucookie_alloc_ref(inp);
			if (cookie == NULL) {
				continue;
			}
			if (nstat_control_source_add(0, state, &nstat_tcp_provider,
			    cookie) != 0) {
				nstat_tucookie_release(cookie);
				break;
			}
		}
	}

	lck_rw_done(&tcbinfo.ipi_lock);

	return result;
}

static void
nstat_tcp_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_tcp_watchers);
}

__private_extern__ void
nstat_tcp_new_pcb(
	struct inpcb    *inp)
{
	struct nstat_tucookie *cookie;

	inp->inp_start_timestamp = mach_continuous_time();

	if (nstat_tcp_watchers == 0) {
		return;
	}

	socket_lock(inp->inp_socket, 0);
	lck_mtx_lock(&nstat_mtx);
	nstat_control_state     *state;
	for (state = nstat_controls; state; state = state->ncs_next) {
		if ((state->ncs_watching & (1 << NSTAT_PROVIDER_TCP_KERNEL)) != 0) {
			// this client is watching tcp
			// acquire a reference for it
			cookie = nstat_tucookie_alloc_ref_locked(inp);
			if (cookie == NULL) {
				continue;
			}
			// add the source, if that fails, release the reference
			if (nstat_control_source_add(0, state,
			    &nstat_tcp_provider, cookie) != 0) {
				nstat_tucookie_release_locked(cookie);
				break;
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
	socket_unlock(inp->inp_socket, 0);
}

__private_extern__ void
nstat_pcb_detach(struct inpcb *inp)
{
	nstat_control_state *state;
	nstat_src *src;
	tailq_head_nstat_src dead_list;
	struct nstat_tucookie *tucookie;
	errno_t result;

	if (inp == NULL || (nstat_tcp_watchers == 0 && nstat_udp_watchers == 0)) {
		return;
	}

	TAILQ_INIT(&dead_list);
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->ncs_mtx);
		TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
		{
			nstat_provider_id_t provider_id = src->provider->nstat_provider_id;
			if (provider_id == NSTAT_PROVIDER_TCP_KERNEL || provider_id == NSTAT_PROVIDER_UDP_KERNEL) {
				tucookie = (struct nstat_tucookie *)src->cookie;
				if (tucookie->inp == inp) {
					break;
				}
			}
		}

		if (src) {
			result = nstat_control_send_goodbye(state, src);

			TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
			TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
		}
		lck_mtx_unlock(&state->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		nstat_control_cleanup_source(NULL, src, TRUE);
	}
}

__private_extern__ void
nstat_pcb_event(struct inpcb *inp, u_int64_t event)
{
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_tucookie *tucookie;
	errno_t result;
	nstat_provider_id_t provider_id;

	if (inp == NULL || (nstat_tcp_watchers == 0 && nstat_udp_watchers == 0)) {
		return;
	}
	if (((merged_filters.mpf_filters[NSTAT_PROVIDER_TCP_KERNEL].mf_events & event) == 0) &&
	    ((merged_filters.mpf_filters[NSTAT_PROVIDER_UDP_KERNEL].mf_events & event) == 0)) {
		// There are clients for TCP and UDP, but none are interested in the event
		// This check saves taking the mutex and scanning the list
		return;
	}
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		if (((state->ncs_provider_filters[NSTAT_PROVIDER_TCP_KERNEL].npf_events & event) == 0) &&
		    ((state->ncs_provider_filters[NSTAT_PROVIDER_UDP_KERNEL].npf_events & event) == 0)) {
			continue;
		}
		lck_mtx_lock(&state->ncs_mtx);
		TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
		{
			provider_id = src->provider->nstat_provider_id;
			if (provider_id == NSTAT_PROVIDER_TCP_KERNEL || provider_id == NSTAT_PROVIDER_UDP_KERNEL) {
				tucookie = (struct nstat_tucookie *)src->cookie;
				if (tucookie->inp == inp) {
					break;
				}
			}
		}

		if (src && ((state->ncs_provider_filters[provider_id].npf_events & event) != 0)) {
			result = nstat_control_send_event(state, src, event);
		}
		lck_mtx_unlock(&state->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}


__private_extern__ void
nstat_pcb_cache(struct inpcb *inp)
{
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_tucookie *tucookie;

	if (inp == NULL || nstat_udp_watchers == 0 ||
	    inp->inp_nstat_refcnt == 0) {
		return;
	}
	VERIFY(SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP);
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->ncs_mtx);
		TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
		{
			tucookie = (struct nstat_tucookie *)src->cookie;
			if (tucookie->inp == inp) {
				if (inp->inp_vflag & INP_IPV6) {
					in6_ip6_to_sockaddr(&inp->in6p_laddr,
					    inp->inp_lport,
					    inp->inp_lifscope,
					    &tucookie->local.v6,
					    sizeof(tucookie->local));
					in6_ip6_to_sockaddr(&inp->in6p_faddr,
					    inp->inp_fport,
					    inp->inp_fifscope,
					    &tucookie->remote.v6,
					    sizeof(tucookie->remote));
				} else if (inp->inp_vflag & INP_IPV4) {
					nstat_ip_to_sockaddr(&inp->inp_laddr,
					    inp->inp_lport,
					    &tucookie->local.v4,
					    sizeof(tucookie->local));
					nstat_ip_to_sockaddr(&inp->inp_faddr,
					    inp->inp_fport,
					    &tucookie->remote.v4,
					    sizeof(tucookie->remote));
				}
				if (inp->inp_last_outifp) {
					tucookie->if_index =
					    inp->inp_last_outifp->if_index;
				}

				tucookie->ifnet_properties = nstat_inpcb_to_flags(inp);
				tucookie->cached = true;
				break;
			}
		}
		lck_mtx_unlock(&state->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

__private_extern__ void
nstat_pcb_invalidate_cache(struct inpcb *inp)
{
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_tucookie *tucookie;

	if (inp == NULL || nstat_udp_watchers == 0 ||
	    inp->inp_nstat_refcnt == 0) {
		return;
	}
	VERIFY(SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP);
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->ncs_mtx);
		TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
		{
			tucookie = (struct nstat_tucookie *)src->cookie;
			if (tucookie->inp == inp) {
				tucookie->cached = false;
				break;
			}
		}
		lck_mtx_unlock(&state->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

static errno_t
nstat_tcp_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *data,
	size_t                  len)
{
	if (len < sizeof(nstat_tcp_descriptor)) {
		return EINVAL;
	}

	if (nstat_tcp_gone(cookie)) {
		return EINVAL;
	}

	nstat_tcp_descriptor    *desc = (nstat_tcp_descriptor*)data;
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb            *inp = tucookie->inp;
	struct tcpcb            *tp = intotcpcb(inp);
	bzero(desc, sizeof(*desc));

	if (inp->inp_vflag & INP_IPV6) {
		in6_ip6_to_sockaddr(&inp->in6p_laddr, inp->inp_lport, inp->inp_lifscope,
		    &desc->local.v6, sizeof(desc->local));
		in6_ip6_to_sockaddr(&inp->in6p_faddr, inp->inp_fport, inp->inp_fifscope,
		    &desc->remote.v6, sizeof(desc->remote));
	} else if (inp->inp_vflag & INP_IPV4) {
		nstat_ip_to_sockaddr(&inp->inp_laddr, inp->inp_lport,
		    &desc->local.v4, sizeof(desc->local));
		nstat_ip_to_sockaddr(&inp->inp_faddr, inp->inp_fport,
		    &desc->remote.v4, sizeof(desc->remote));
	}

	desc->state = intotcpcb(inp)->t_state;
	desc->ifindex = (inp->inp_last_outifp == NULL) ? 0 :
	    inp->inp_last_outifp->if_index;

	// danger - not locked, values could be bogus
	desc->txunacked = tp->snd_max - tp->snd_una;
	desc->txwindow = tp->snd_wnd;
	desc->txcwindow = tp->snd_cwnd;
	desc->ifnet_properties = nstat_inpcb_to_flags(inp);

	if (CC_ALGO(tp)->name != NULL) {
		strlcpy(desc->cc_algo, CC_ALGO(tp)->name,
		    sizeof(desc->cc_algo));
	}

	struct socket *so = inp->inp_socket;
	if (so) {
		// TBD - take the socket lock around these to make sure
		// they're in sync?
		desc->upid = so->last_upid;
		desc->pid = so->last_pid;
		desc->traffic_class = so->so_traffic_class;
		if ((so->so_flags1 & SOF1_TRAFFIC_MGT_SO_BACKGROUND)) {
			desc->traffic_mgt_flags |= TRAFFIC_MGT_SO_BACKGROUND;
		}
		if ((so->so_flags1 & SOF1_TRAFFIC_MGT_TCP_RECVBG)) {
			desc->traffic_mgt_flags |= TRAFFIC_MGT_TCP_RECVBG;
		}
		if (so->so_flags1 & SOF1_INBOUND) {
			desc->ifnet_properties |= NSTAT_SOURCE_IS_INBOUND;
		} else if (desc->state == TCPS_LISTEN) {
			desc->ifnet_properties |= NSTAT_SOURCE_IS_LISTENER;
			tucookie->ifnet_properties = NSTAT_SOURCE_IS_LISTENER;
		} else if (desc->state != TCPS_CLOSED) {
			desc->ifnet_properties |= NSTAT_SOURCE_IS_OUTBOUND;
			tucookie->ifnet_properties = NSTAT_SOURCE_IS_OUTBOUND;
		} else {
			desc->ifnet_properties |= tucookie->ifnet_properties;
		}
		proc_name(desc->pid, desc->pname, sizeof(desc->pname));
		if (desc->pname[0] == 0) {
			strlcpy(desc->pname, tucookie->pname,
			    sizeof(desc->pname));
		} else {
			desc->pname[sizeof(desc->pname) - 1] = 0;
			strlcpy(tucookie->pname, desc->pname,
			    sizeof(tucookie->pname));
		}
		memcpy(desc->uuid, so->last_uuid, sizeof(so->last_uuid));
		memcpy(desc->vuuid, so->so_vuuid, sizeof(so->so_vuuid));
		if (so->so_flags & SOF_DELEGATED) {
			desc->eupid = so->e_upid;
			desc->epid = so->e_pid;
			memcpy(desc->euuid, so->e_uuid, sizeof(so->e_uuid));
		} else {
			desc->eupid = desc->upid;
			desc->epid = desc->pid;
			memcpy(desc->euuid, desc->uuid, sizeof(desc->uuid));
		}
		uuid_copy(desc->fuuid, inp->necp_client_uuid);
		desc->persona_id = so->so_persona_id;
		desc->uid = kauth_cred_getuid(so->so_cred);
		desc->sndbufsize = so->so_snd.sb_hiwat;
		desc->sndbufused = so->so_snd.sb_cc;
		desc->rcvbufsize = so->so_rcv.sb_hiwat;
		desc->rcvbufused = so->so_rcv.sb_cc;
		desc->fallback_mode = so->so_fallback_mode;

		if (nstat_debug) {
			uuid_string_t euuid_str = { 0 };
			uuid_unparse(desc->euuid, euuid_str);
			NSTAT_DEBUG_SOCKET_LOG(so, "NSTAT: TCP - pid %d uid %d euuid %s persona id %d", desc->pid, desc->uid, euuid_str, desc->persona_id);
		}
	}

	tcp_get_connectivity_status(tp, &desc->connstatus);
	inp_get_activity_bitmap(inp, &desc->activity_bitmap);
	desc->start_timestamp = inp->inp_start_timestamp;
	desc->timestamp = mach_continuous_time();
	return 0;
}

static bool
nstat_tcpudp_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter, bool is_UDP)
{
	bool retval = true;

	if ((filter->npf_flags & (NSTAT_FILTER_IFNET_FLAGS | NSTAT_FILTER_SPECIFIC_USER)) != 0) {
		struct nstat_tucookie *tucookie = (struct nstat_tucookie *)cookie;
		struct inpcb *inp = tucookie->inp;

		/* Only apply interface filter if at least one is allowed. */
		if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0) {
			uint32_t interface_properties = nstat_inpcb_to_flags(inp);

			if ((filter->npf_flags & interface_properties) == 0) {
				// For UDP, we could have an undefined interface and yet transfers may have occurred.
				// We allow reporting if there have been transfers of the requested kind.
				// This is imperfect as we cannot account for the expensive attribute over wifi.
				// We also assume that cellular is expensive and we have no way to select for AWDL
				if (is_UDP) {
					do{
						if ((filter->npf_flags & (NSTAT_FILTER_ACCEPT_CELLULAR | NSTAT_FILTER_ACCEPT_EXPENSIVE)) &&
						    (inp->inp_cstat->rxbytes || inp->inp_cstat->txbytes)) {
							break;
						}
						if ((filter->npf_flags & NSTAT_FILTER_ACCEPT_WIFI) &&
						    (inp->inp_wstat->rxbytes || inp->inp_wstat->txbytes)) {
							break;
						}
						if ((filter->npf_flags & NSTAT_FILTER_ACCEPT_WIRED) &&
						    (inp->inp_Wstat->rxbytes || inp->inp_Wstat->txbytes)) {
							break;
						}
						return false;
					} while (0);
				} else {
					return false;
				}
			}
		}

		if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) && (retval)) {
			struct socket *so = inp->inp_socket;
			retval = false;

			if (so) {
				if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_PID) != 0) &&
				    (filter->npf_pid == so->last_pid)) {
					retval = true;
				} else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EPID) != 0) &&
				    (filter->npf_pid == (so->so_flags & SOF_DELEGATED)? so->e_upid : so->last_pid)) {
					retval = true;
				} else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_UUID) != 0) &&
				    (memcmp(filter->npf_uuid, so->last_uuid, sizeof(so->last_uuid)) == 0)) {
					retval = true;
				} else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EUUID) != 0) &&
				    (memcmp(filter->npf_uuid, (so->so_flags & SOF_DELEGATED)? so->e_uuid : so->last_uuid,
				    sizeof(so->last_uuid)) == 0)) {
					retval = true;
				}
			}
		}
	}
	return retval;
}

static bool
nstat_tcp_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	__unused u_int64_t suppression_flags)
{
	return nstat_tcpudp_reporting_allowed(cookie, filter, FALSE);
}

static size_t
nstat_tcp_extensions(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *buf, size_t len)
{
	struct nstat_tucookie *tucookie =  (struct nstat_tucookie *)cookie;
	struct inpcb          *inp = tucookie->inp;

	if (nstat_tcp_gone(cookie)) {
		return 0;
	}

	switch (extension_id) {
	case NSTAT_EXTENDED_UPDATE_TYPE_DOMAIN:
		return nstat_inp_domain_info(inp, (nstat_domain_info *)buf, len);

	case NSTAT_EXTENDED_UPDATE_TYPE_NECP_TLV:
	default:
		break;
	}
	return 0;
}

static void
nstat_init_tcp_provider(void)
{
	bzero(&nstat_tcp_provider, sizeof(nstat_tcp_provider));
	nstat_tcp_provider.nstat_descriptor_length = sizeof(nstat_tcp_descriptor);
	nstat_tcp_provider.nstat_provider_id = NSTAT_PROVIDER_TCP_KERNEL;
	nstat_tcp_provider.nstat_lookup = nstat_tcp_lookup;
	nstat_tcp_provider.nstat_gone = nstat_tcp_gone;
	nstat_tcp_provider.nstat_counts = nstat_tcp_counts;
	nstat_tcp_provider.nstat_release = nstat_tcp_release;
	nstat_tcp_provider.nstat_watcher_add = nstat_tcp_add_watcher;
	nstat_tcp_provider.nstat_watcher_remove = nstat_tcp_remove_watcher;
	nstat_tcp_provider.nstat_copy_descriptor = nstat_tcp_copy_descriptor;
	nstat_tcp_provider.nstat_reporting_allowed = nstat_tcp_reporting_allowed;
	nstat_tcp_provider.nstat_copy_extension = nstat_tcp_extensions;
	nstat_tcp_provider.next = nstat_providers;
	nstat_providers = &nstat_tcp_provider;
}

#pragma mark -- UDP Provider --

static nstat_provider   nstat_udp_provider;

static errno_t
nstat_udp_lookup(
	__unused const void              *data,
	__unused u_int32_t               length,
	__unused nstat_provider_cookie_t *out_cookie)
{
	// Looking up a specific connection is not supported.
	return ENOTSUP;
}

static int
nstat_udp_gone(
	nstat_provider_cookie_t cookie)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb *inp;

	return (!(inp = tucookie->inp) ||
	       inp->inp_state == INPCB_STATE_DEAD) ? 1 : 0;
}

static errno_t
nstat_udp_counts(
	nstat_provider_cookie_t cookie,
	struct nstat_counts     *out_counts,
	int                     *out_gone)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;

	if (out_gone) {
		*out_gone = 0;
	}

	// if the pcb is in the dead state, we should stop using it
	if (nstat_udp_gone(cookie)) {
		if (out_gone) {
			*out_gone = 1;
		}
		if (!tucookie->inp) {
			return EINVAL;
		}
	}
	struct inpcb *inp = tucookie->inp;

	out_counts->nstat_rxpackets = os_atomic_load(&inp->inp_stat->rxpackets, relaxed);
	out_counts->nstat_rxbytes = os_atomic_load(&inp->inp_stat->rxbytes, relaxed);
	out_counts->nstat_txpackets = os_atomic_load(&inp->inp_stat->txpackets, relaxed);
	out_counts->nstat_txbytes = os_atomic_load(&inp->inp_stat->txbytes, relaxed);
	out_counts->nstat_cell_rxbytes = os_atomic_load(&inp->inp_cstat->rxbytes, relaxed);
	out_counts->nstat_cell_txbytes = os_atomic_load(&inp->inp_cstat->txbytes, relaxed);
	out_counts->nstat_wifi_rxbytes = os_atomic_load(&inp->inp_wstat->rxbytes, relaxed);
	out_counts->nstat_wifi_txbytes = os_atomic_load(&inp->inp_wstat->txbytes, relaxed);
	out_counts->nstat_wired_rxbytes = os_atomic_load(&inp->inp_Wstat->rxbytes, relaxed);
	out_counts->nstat_wired_txbytes = os_atomic_load(&inp->inp_Wstat->txbytes, relaxed);

	return 0;
}

static void
nstat_udp_release(
	nstat_provider_cookie_t cookie,
	int locked)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;

	nstat_tucookie_release_internal(tucookie, locked);
}

static errno_t
nstat_udp_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs  *req)
{
	// There is a tricky issue around getting all UDP sockets added once
	// and only once.  nstat_udp_new_pcb() is called prior to the new item
	// being placed on any lists where it might be found.
	// By locking the udpinfo.ipi_lock prior to marking the state as a watcher,
	// it should be impossible for a new socket to be added twice.
	// On the other hand, there is still a timing issue where a new socket
	// results in a call to nstat_udp_new_pcb() before this watcher
	// is instantiated and yet the socket doesn't make it into ipi_listhead
	// prior to the scan. <rdar://problem/30361716>

	errno_t result;

	lck_rw_lock_shared(&udbinfo.ipi_lock);
	result = nstat_set_provider_filter(state, req);

	if (result == 0) {
		struct inpcb *inp;
		struct nstat_tucookie *cookie;

		OSIncrementAtomic(&nstat_udp_watchers);

		// Add all current UDP inpcbs.
		LIST_FOREACH(inp, udbinfo.ipi_listhead, inp_list)
		{
			cookie = nstat_tucookie_alloc_ref(inp);
			if (cookie == NULL) {
				continue;
			}
			if (nstat_control_source_add(0, state, &nstat_udp_provider,
			    cookie) != 0) {
				nstat_tucookie_release(cookie);
				break;
			}
		}
	}

	lck_rw_done(&udbinfo.ipi_lock);

	return result;
}

static void
nstat_udp_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_udp_watchers);
}

__private_extern__ void
nstat_udp_new_pcb(
	struct inpcb    *inp)
{
	struct nstat_tucookie *cookie;

	inp->inp_start_timestamp = mach_continuous_time();

	if (nstat_udp_watchers == 0) {
		return;
	}

	socket_lock(inp->inp_socket, 0);
	lck_mtx_lock(&nstat_mtx);
	nstat_control_state     *state;
	for (state = nstat_controls; state; state = state->ncs_next) {
		if ((state->ncs_watching & (1 << NSTAT_PROVIDER_UDP_KERNEL)) != 0) {
			// this client is watching tcp
			// acquire a reference for it
			cookie = nstat_tucookie_alloc_ref_locked(inp);
			if (cookie == NULL) {
				continue;
			}
			// add the source, if that fails, release the reference
			if (nstat_control_source_add(0, state,
			    &nstat_udp_provider, cookie) != 0) {
				nstat_tucookie_release_locked(cookie);
				break;
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
	socket_unlock(inp->inp_socket, 0);
}

static errno_t
nstat_udp_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *data,
	size_t                  len)
{
	if (len < sizeof(nstat_udp_descriptor)) {
		return EINVAL;
	}

	if (nstat_udp_gone(cookie)) {
		return EINVAL;
	}

	struct nstat_tucookie   *tucookie =
	    (struct nstat_tucookie *)cookie;
	nstat_udp_descriptor    *desc = (nstat_udp_descriptor*)data;
	struct inpcb            *inp = tucookie->inp;

	bzero(desc, sizeof(*desc));

	if (tucookie->cached == false) {
		if (inp->inp_vflag & INP_IPV6) {
			in6_ip6_to_sockaddr(&inp->in6p_laddr, inp->inp_lport, inp->inp_lifscope,
			    &desc->local.v6, sizeof(desc->local.v6));
			in6_ip6_to_sockaddr(&inp->in6p_faddr, inp->inp_fport, inp->inp_fifscope,
			    &desc->remote.v6, sizeof(desc->remote.v6));
		} else if (inp->inp_vflag & INP_IPV4) {
			nstat_ip_to_sockaddr(&inp->inp_laddr, inp->inp_lport,
			    &desc->local.v4, sizeof(desc->local.v4));
			nstat_ip_to_sockaddr(&inp->inp_faddr, inp->inp_fport,
			    &desc->remote.v4, sizeof(desc->remote.v4));
		}
		desc->ifnet_properties = nstat_inpcb_to_flags(inp);
	} else {
		if (inp->inp_vflag & INP_IPV6) {
			memcpy(&desc->local.v6, &tucookie->local.v6,
			    sizeof(desc->local.v6));
			memcpy(&desc->remote.v6, &tucookie->remote.v6,
			    sizeof(desc->remote.v6));
		} else if (inp->inp_vflag & INP_IPV4) {
			memcpy(&desc->local.v4, &tucookie->local.v4,
			    sizeof(desc->local.v4));
			memcpy(&desc->remote.v4, &tucookie->remote.v4,
			    sizeof(desc->remote.v4));
		}
		desc->ifnet_properties = tucookie->ifnet_properties;
	}

	if (inp->inp_last_outifp) {
		desc->ifindex = inp->inp_last_outifp->if_index;
	} else {
		desc->ifindex = tucookie->if_index;
	}

	struct socket *so = inp->inp_socket;
	if (so) {
		// TBD - take the socket lock around these to make sure
		// they're in sync?
		desc->upid = so->last_upid;
		desc->pid = so->last_pid;
		proc_name(desc->pid, desc->pname, sizeof(desc->pname));
		if (desc->pname[0] == 0) {
			strlcpy(desc->pname, tucookie->pname,
			    sizeof(desc->pname));
		} else {
			desc->pname[sizeof(desc->pname) - 1] = 0;
			strlcpy(tucookie->pname, desc->pname,
			    sizeof(tucookie->pname));
		}
		memcpy(desc->uuid, so->last_uuid, sizeof(so->last_uuid));
		memcpy(desc->vuuid, so->so_vuuid, sizeof(so->so_vuuid));
		if (so->so_flags & SOF_DELEGATED) {
			desc->eupid = so->e_upid;
			desc->epid = so->e_pid;
			memcpy(desc->euuid, so->e_uuid, sizeof(so->e_uuid));
		} else {
			desc->eupid = desc->upid;
			desc->epid = desc->pid;
			memcpy(desc->euuid, desc->uuid, sizeof(desc->uuid));
		}
		uuid_copy(desc->fuuid, inp->necp_client_uuid);
		desc->persona_id = so->so_persona_id;
		desc->uid = kauth_cred_getuid(so->so_cred);
		desc->rcvbufsize = so->so_rcv.sb_hiwat;
		desc->rcvbufused = so->so_rcv.sb_cc;
		desc->traffic_class = so->so_traffic_class;
		desc->fallback_mode = so->so_fallback_mode;
		inp_get_activity_bitmap(inp, &desc->activity_bitmap);
		desc->start_timestamp = inp->inp_start_timestamp;
		desc->timestamp = mach_continuous_time();

		if (nstat_debug) {
			uuid_string_t euuid_str = { 0 };
			uuid_unparse(desc->euuid, euuid_str);
			NSTAT_DEBUG_SOCKET_LOG(so, "NSTAT: UDP - pid %d uid %d euuid %s persona id %d", desc->pid, desc->uid, euuid_str, desc->persona_id);
		}
	}

	return 0;
}

static bool
nstat_udp_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	__unused u_int64_t suppression_flags)
{
	return nstat_tcpudp_reporting_allowed(cookie, filter, TRUE);
}


static size_t
nstat_udp_extensions(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *buf, size_t len)
{
	struct nstat_tucookie *tucookie =  (struct nstat_tucookie *)cookie;
	struct inpcb          *inp = tucookie->inp;
	if (nstat_udp_gone(cookie)) {
		return 0;
	}

	switch (extension_id) {
	case NSTAT_EXTENDED_UPDATE_TYPE_DOMAIN:
		return nstat_inp_domain_info(inp, (nstat_domain_info *)buf, len);

	default:
		break;
	}
	return 0;
}


static void
nstat_init_udp_provider(void)
{
	bzero(&nstat_udp_provider, sizeof(nstat_udp_provider));
	nstat_udp_provider.nstat_provider_id = NSTAT_PROVIDER_UDP_KERNEL;
	nstat_udp_provider.nstat_descriptor_length = sizeof(nstat_udp_descriptor);
	nstat_udp_provider.nstat_lookup = nstat_udp_lookup;
	nstat_udp_provider.nstat_gone = nstat_udp_gone;
	nstat_udp_provider.nstat_counts = nstat_udp_counts;
	nstat_udp_provider.nstat_watcher_add = nstat_udp_add_watcher;
	nstat_udp_provider.nstat_watcher_remove = nstat_udp_remove_watcher;
	nstat_udp_provider.nstat_copy_descriptor = nstat_udp_copy_descriptor;
	nstat_udp_provider.nstat_release = nstat_udp_release;
	nstat_udp_provider.nstat_reporting_allowed = nstat_udp_reporting_allowed;
	nstat_udp_provider.nstat_copy_extension = nstat_udp_extensions;
	nstat_udp_provider.next = nstat_providers;
	nstat_providers = &nstat_udp_provider;
}

#if SKYWALK

#pragma mark -- TCP/UDP/QUIC Userland

// Almost all of this infrastucture is common to both TCP and UDP

static u_int32_t    nstat_userland_quic_watchers = 0;
static u_int32_t    nstat_userland_udp_watchers = 0;
static u_int32_t    nstat_userland_tcp_watchers = 0;

static u_int32_t    nstat_userland_quic_shadows = 0;
static u_int32_t    nstat_userland_udp_shadows = 0;
static u_int32_t    nstat_userland_tcp_shadows = 0;

static nstat_provider   nstat_userland_quic_provider;
static nstat_provider   nstat_userland_udp_provider;
static nstat_provider   nstat_userland_tcp_provider;

enum nstat_rnf_override {
	nstat_rnf_override_not_set,
	nstat_rnf_override_enabled,
	nstat_rnf_override_disabled
};

struct nstat_tu_shadow {
	tailq_entry_tu_shadow                   shad_link;
	userland_stats_request_vals_fn          *shad_getvals_fn;
	userland_stats_request_extension_fn     *shad_get_extension_fn;
	userland_stats_provider_context         *shad_provider_context;
	u_int64_t                               shad_properties;
	u_int64_t                               shad_start_timestamp;
	nstat_provider_id_t                     shad_provider;
	struct nstat_procdetails                *shad_procdetails;
	bool                                    shad_live;  // false if defunct
	enum nstat_rnf_override                 shad_rnf_override;
	uint32_t                                shad_magic;
};

// Magic number checking should remain in place until the userland provider has been fully proven
#define TU_SHADOW_MAGIC             0xfeedf00d
#define TU_SHADOW_UNMAGIC           0xdeaddeed

static tailq_head_tu_shadow nstat_userprot_shad_head = TAILQ_HEAD_INITIALIZER(nstat_userprot_shad_head);

static errno_t
nstat_userland_tu_lookup(
	__unused const void                 *data,
	__unused u_int32_t                  length,
	__unused nstat_provider_cookie_t    *out_cookie)
{
	// Looking up a specific connection is not supported
	return ENOTSUP;
}

static int
nstat_userland_tu_gone(
	__unused nstat_provider_cookie_t    cookie)
{
	// Returns non-zero if the source has gone.
	// We don't keep a source hanging around, so the answer is always 0
	return 0;
}

static errno_t
nstat_userland_tu_counts(
	nstat_provider_cookie_t cookie,
	struct nstat_counts     *out_counts,
	int                     *out_gone)
{
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;
	assert(shad->shad_magic == TU_SHADOW_MAGIC);
	assert(shad->shad_live);

	bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, NULL, out_counts, NULL);

	if (out_gone) {
		*out_gone = 0;
	}

	return (result)? 0 : EIO;
}


static errno_t
nstat_userland_tu_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *data,
	__unused size_t         len)
{
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;
	assert(shad->shad_magic == TU_SHADOW_MAGIC);
	assert(shad->shad_live);
	struct nstat_procdetails *procdetails = shad->shad_procdetails;
	assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

	bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, NULL, NULL, data);

	switch (shad->shad_provider) {
	case NSTAT_PROVIDER_TCP_USERLAND:
	{
		nstat_tcp_descriptor *desc = (nstat_tcp_descriptor *)data;
		desc->pid = procdetails->pdet_pid;
		desc->upid = procdetails->pdet_upid;
		uuid_copy(desc->uuid, procdetails->pdet_uuid);
		strlcpy(desc->pname, procdetails->pdet_procname, sizeof(desc->pname));
		if (shad->shad_rnf_override == nstat_rnf_override_enabled) {
			desc->ifnet_properties |= NSTAT_IFNET_VIA_CELLFALLBACK;
			desc->fallback_mode = SO_FALLBACK_MODE_FAST;
		} else if (shad->shad_rnf_override == nstat_rnf_override_disabled) {
			desc->ifnet_properties &= ~NSTAT_IFNET_VIA_CELLFALLBACK;
			desc->fallback_mode = SO_FALLBACK_MODE_NONE;
		}
		desc->ifnet_properties |= (uint32_t)shad->shad_properties;
		desc->start_timestamp = shad->shad_start_timestamp;
		desc->timestamp = mach_continuous_time();
	}
	break;
	case NSTAT_PROVIDER_UDP_USERLAND:
	{
		nstat_udp_descriptor *desc = (nstat_udp_descriptor *)data;
		desc->pid = procdetails->pdet_pid;
		desc->upid = procdetails->pdet_upid;
		uuid_copy(desc->uuid, procdetails->pdet_uuid);
		strlcpy(desc->pname, procdetails->pdet_procname, sizeof(desc->pname));
		if (shad->shad_rnf_override == nstat_rnf_override_enabled) {
			desc->ifnet_properties |= NSTAT_IFNET_VIA_CELLFALLBACK;
			desc->fallback_mode = SO_FALLBACK_MODE_FAST;
		} else if (shad->shad_rnf_override == nstat_rnf_override_disabled) {
			desc->ifnet_properties &= ~NSTAT_IFNET_VIA_CELLFALLBACK;
			desc->fallback_mode = SO_FALLBACK_MODE_NONE;
		}
		desc->ifnet_properties |= (uint32_t)shad->shad_properties;
		desc->start_timestamp = shad->shad_start_timestamp;
		desc->timestamp = mach_continuous_time();
	}
	break;
	case NSTAT_PROVIDER_QUIC_USERLAND:
	{
		nstat_quic_descriptor *desc = (nstat_quic_descriptor *)data;
		desc->pid = procdetails->pdet_pid;
		desc->upid = procdetails->pdet_upid;
		uuid_copy(desc->uuid, procdetails->pdet_uuid);
		strlcpy(desc->pname, procdetails->pdet_procname, sizeof(desc->pname));
		if (shad->shad_rnf_override == nstat_rnf_override_enabled) {
			desc->ifnet_properties |= NSTAT_IFNET_VIA_CELLFALLBACK;
			desc->fallback_mode = SO_FALLBACK_MODE_FAST;
		} else if (shad->shad_rnf_override == nstat_rnf_override_disabled) {
			desc->ifnet_properties &= ~NSTAT_IFNET_VIA_CELLFALLBACK;
			desc->fallback_mode = SO_FALLBACK_MODE_NONE;
		}
		desc->ifnet_properties |= (uint32_t)shad->shad_properties;
		desc->start_timestamp = shad->shad_start_timestamp;
		desc->timestamp = mach_continuous_time();
	}
	break;
	default:
		break;
	}
	return (result)? 0 : EIO;
}

static void
nstat_userland_tu_release(
	__unused nstat_provider_cookie_t    cookie,
	__unused int locked)
{
	// Called when a nstat_src is detached.
	// We don't reference count or ask for delayed release so nothing to do here.
	// Note that any associated nstat_tu_shadow may already have been released.
}

static bool
check_reporting_for_user(nstat_provider_filter *filter, pid_t pid, pid_t epid, uuid_t *uuid, uuid_t *euuid)
{
	bool retval = true;

	if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) {
		retval = false;

		if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_PID) != 0) &&
		    (filter->npf_pid == pid)) {
			retval = true;
		} else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EPID) != 0) &&
		    (filter->npf_pid == epid)) {
			retval = true;
		} else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_UUID) != 0) &&
		    (memcmp(filter->npf_uuid, uuid, sizeof(*uuid)) == 0)) {
			retval = true;
		} else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EUUID) != 0) &&
		    (memcmp(filter->npf_uuid, euuid, sizeof(*euuid)) == 0)) {
			retval = true;
		}
	}
	return retval;
}

static bool
nstat_userland_tcp_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	__unused u_int64_t suppression_flags)
{
	bool retval = true;
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;

	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0) {
		u_int16_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL)) {
			u_int32_t extended_ifflags = extend_ifnet_flags(ifflags);
			if ((filter->npf_flags & extended_ifflags) == 0) {
				return false;
			}
		}
	}

	if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) {
		nstat_tcp_descriptor tcp_desc;  // Stack allocation - OK or pushing the limits too far?
		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, NULL, NULL, &tcp_desc)) {
			retval = check_reporting_for_user(filter, (pid_t)tcp_desc.pid, (pid_t)tcp_desc.epid,
			    &tcp_desc.uuid, &tcp_desc.euuid);
		} else {
			retval = false; // No further information, so might as well give up now.
		}
	}
	return retval;
}

static size_t
nstat_userland_extensions(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *buf, size_t len)
{
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;
	assert(shad->shad_magic == TU_SHADOW_MAGIC);
	assert(shad->shad_live);
	assert(shad->shad_procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

	return shad->shad_get_extension_fn(shad->shad_provider_context, extension_id, buf, len);
}


static bool
nstat_userland_udp_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	__unused u_int64_t suppression_flags)
{
	bool retval = true;
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;

	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0) {
		u_int16_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL)) {
			u_int32_t extended_ifflags = extend_ifnet_flags(ifflags);
			if ((filter->npf_flags & extended_ifflags) == 0) {
				return false;
			}
		}
	}
	if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) {
		nstat_udp_descriptor udp_desc;  // Stack allocation - OK or pushing the limits too far?
		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, NULL, NULL, &udp_desc)) {
			retval = check_reporting_for_user(filter, (pid_t)udp_desc.pid, (pid_t)udp_desc.epid,
			    &udp_desc.uuid, &udp_desc.euuid);
		} else {
			retval = false; // No further information, so might as well give up now.
		}
	}
	return retval;
}

static bool
nstat_userland_quic_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	__unused u_int64_t suppression_flags)
{
	bool retval = true;
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;

	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0) {
		u_int16_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL)) {
			u_int32_t extended_ifflags = extend_ifnet_flags(ifflags);
			if ((filter->npf_flags & extended_ifflags) == 0) {
				return false;
			}
		}
	}
	if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) {
		nstat_quic_descriptor quic_desc;  // Stack allocation - OK or pushing the limits too far?
		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, NULL, NULL, &quic_desc)) {
			retval = check_reporting_for_user(filter, (pid_t)quic_desc.pid, (pid_t)quic_desc.epid,
			    &quic_desc.uuid, &quic_desc.euuid);
		} else {
			retval = false; // No further information, so might as well give up now.
		}
	}
	return retval;
}

static errno_t
nstat_userland_protocol_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs  *req,
	nstat_provider_type_t   nstat_provider_type,
	nstat_provider          *nstat_provider,
	u_int32_t               *proto_watcher_cnt)
{
	errno_t result;

	lck_mtx_lock(&nstat_mtx);
	result = nstat_set_provider_filter(state, req);

	if (result == 0) {
		struct nstat_tu_shadow *shad;

		OSIncrementAtomic(proto_watcher_cnt);

		TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
			assert(shad->shad_magic == TU_SHADOW_MAGIC);

			if ((shad->shad_provider == nstat_provider_type) && (shad->shad_live)) {
				result = nstat_control_source_add(0, state, nstat_provider, shad);
				if (result != 0) {
					printf("%s - nstat_control_source_add returned %d for "
					    "provider type: %d\n", __func__, result, nstat_provider_type);
					break;
				}
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return result;
}

static errno_t
nstat_userland_tcp_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs  *req)
{
	return nstat_userland_protocol_add_watcher(state, req, NSTAT_PROVIDER_TCP_USERLAND,
	           &nstat_userland_tcp_provider, &nstat_userland_tcp_watchers);
}

static errno_t
nstat_userland_udp_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs *req)
{
	return nstat_userland_protocol_add_watcher(state, req, NSTAT_PROVIDER_UDP_USERLAND,
	           &nstat_userland_udp_provider, &nstat_userland_udp_watchers);
}

static errno_t
nstat_userland_quic_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs *req)
{
	return nstat_userland_protocol_add_watcher(state, req, NSTAT_PROVIDER_QUIC_USERLAND,
	           &nstat_userland_quic_provider, &nstat_userland_quic_watchers);
}

static void
nstat_userland_tcp_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_userland_tcp_watchers);
}

static void
nstat_userland_udp_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_userland_udp_watchers);
}

static void
nstat_userland_quic_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_userland_quic_watchers);
}


static void
nstat_init_userland_tcp_provider(void)
{
	bzero(&nstat_userland_tcp_provider, sizeof(nstat_userland_tcp_provider));
	nstat_userland_tcp_provider.nstat_descriptor_length = sizeof(nstat_tcp_descriptor);
	nstat_userland_tcp_provider.nstat_provider_id = NSTAT_PROVIDER_TCP_USERLAND;
	nstat_userland_tcp_provider.nstat_lookup = nstat_userland_tu_lookup;
	nstat_userland_tcp_provider.nstat_gone = nstat_userland_tu_gone;
	nstat_userland_tcp_provider.nstat_counts = nstat_userland_tu_counts;
	nstat_userland_tcp_provider.nstat_release = nstat_userland_tu_release;
	nstat_userland_tcp_provider.nstat_watcher_add = nstat_userland_tcp_add_watcher;
	nstat_userland_tcp_provider.nstat_watcher_remove = nstat_userland_tcp_remove_watcher;
	nstat_userland_tcp_provider.nstat_copy_descriptor = nstat_userland_tu_copy_descriptor;
	nstat_userland_tcp_provider.nstat_reporting_allowed = nstat_userland_tcp_reporting_allowed;
	nstat_userland_tcp_provider.nstat_copy_extension = nstat_userland_extensions;
	nstat_userland_tcp_provider.next = nstat_providers;
	nstat_providers = &nstat_userland_tcp_provider;
}


static void
nstat_init_userland_udp_provider(void)
{
	bzero(&nstat_userland_udp_provider, sizeof(nstat_userland_udp_provider));
	nstat_userland_udp_provider.nstat_descriptor_length = sizeof(nstat_udp_descriptor);
	nstat_userland_udp_provider.nstat_provider_id = NSTAT_PROVIDER_UDP_USERLAND;
	nstat_userland_udp_provider.nstat_lookup = nstat_userland_tu_lookup;
	nstat_userland_udp_provider.nstat_gone = nstat_userland_tu_gone;
	nstat_userland_udp_provider.nstat_counts = nstat_userland_tu_counts;
	nstat_userland_udp_provider.nstat_release = nstat_userland_tu_release;
	nstat_userland_udp_provider.nstat_watcher_add = nstat_userland_udp_add_watcher;
	nstat_userland_udp_provider.nstat_watcher_remove = nstat_userland_udp_remove_watcher;
	nstat_userland_udp_provider.nstat_copy_descriptor = nstat_userland_tu_copy_descriptor;
	nstat_userland_udp_provider.nstat_reporting_allowed = nstat_userland_udp_reporting_allowed;
	nstat_userland_udp_provider.nstat_copy_extension = nstat_userland_extensions;
	nstat_userland_udp_provider.next = nstat_providers;
	nstat_providers = &nstat_userland_udp_provider;
}

static void
nstat_init_userland_quic_provider(void)
{
	bzero(&nstat_userland_quic_provider, sizeof(nstat_userland_quic_provider));
	nstat_userland_quic_provider.nstat_descriptor_length = sizeof(nstat_quic_descriptor);
	nstat_userland_quic_provider.nstat_provider_id = NSTAT_PROVIDER_QUIC_USERLAND;
	nstat_userland_quic_provider.nstat_lookup = nstat_userland_tu_lookup;
	nstat_userland_quic_provider.nstat_gone = nstat_userland_tu_gone;
	nstat_userland_quic_provider.nstat_counts = nstat_userland_tu_counts;
	nstat_userland_quic_provider.nstat_release = nstat_userland_tu_release;
	nstat_userland_quic_provider.nstat_watcher_add = nstat_userland_quic_add_watcher;
	nstat_userland_quic_provider.nstat_watcher_remove = nstat_userland_quic_remove_watcher;
	nstat_userland_quic_provider.nstat_copy_descriptor = nstat_userland_tu_copy_descriptor;
	nstat_userland_quic_provider.nstat_reporting_allowed = nstat_userland_quic_reporting_allowed;
	nstat_userland_quic_provider.nstat_copy_extension = nstat_userland_extensions;
	nstat_userland_quic_provider.next = nstat_providers;
	nstat_providers = &nstat_userland_quic_provider;
}


// Things get started with a call to netstats to say that there’s a new connection:
__private_extern__ nstat_userland_context
ntstat_userland_stats_open(userland_stats_provider_context *ctx,
    int provider_id,
    u_int64_t properties,
    userland_stats_request_vals_fn req_fn,
    userland_stats_request_extension_fn req_extension_fn)
{
	struct nstat_tu_shadow *shad;
	struct nstat_procdetails *procdetails;
	nstat_provider *provider;

	if ((provider_id != NSTAT_PROVIDER_TCP_USERLAND) &&
	    (provider_id != NSTAT_PROVIDER_UDP_USERLAND) &&
	    (provider_id != NSTAT_PROVIDER_QUIC_USERLAND)) {
		printf("%s - incorrect provider is supplied, %d\n", __func__, provider_id);
		return NULL;
	}

	shad = kalloc_type(struct nstat_tu_shadow, Z_WAITOK | Z_NOFAIL);

	procdetails = nstat_retain_curprocdetails();

	if (procdetails == NULL) {
		kfree_type(struct nstat_tu_shadow, shad);
		return NULL;
	}

	shad->shad_getvals_fn         = req_fn;
	shad->shad_get_extension_fn   = req_extension_fn;
	shad->shad_provider_context   = ctx;
	shad->shad_provider           = provider_id;
	shad->shad_properties         = properties;
	shad->shad_procdetails        = procdetails;
	shad->shad_rnf_override       = nstat_rnf_override_not_set;
	shad->shad_start_timestamp    = mach_continuous_time();
	shad->shad_live               = true;
	shad->shad_magic              = TU_SHADOW_MAGIC;

	lck_mtx_lock(&nstat_mtx);
	nstat_control_state     *state;

	// Even if there are no watchers, we save the shadow structure
	TAILQ_INSERT_HEAD(&nstat_userprot_shad_head, shad, shad_link);

	if (provider_id == NSTAT_PROVIDER_TCP_USERLAND) {
		nstat_userland_tcp_shadows++;
		provider = &nstat_userland_tcp_provider;
	} else if (provider_id == NSTAT_PROVIDER_UDP_USERLAND) {
		nstat_userland_udp_shadows++;
		provider = &nstat_userland_udp_provider;
	} else {
		nstat_userland_quic_shadows++;
		provider = &nstat_userland_quic_provider;
	}

	for (state = nstat_controls; state; state = state->ncs_next) {
		if ((state->ncs_watching & (1 << provider_id)) != 0) {
			// this client is watching tcp/udp/quic userland
			// Link to it.
			int result = nstat_control_source_add(0, state, provider, shad);
			if (result != 0) {
				// There should be some kind of statistics for failures like this.
				// <rdar://problem/31377195> The kernel ntstat component should keep some
				// internal counters reflecting operational state for eventual AWD reporting
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return (nstat_userland_context)shad;
}


__private_extern__ void
ntstat_userland_stats_close(nstat_userland_context nstat_ctx)
{
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)nstat_ctx;
	tailq_head_nstat_src dead_list;
	nstat_src *src;

	if (shad == NULL) {
		return;
	}

	assert(shad->shad_magic == TU_SHADOW_MAGIC);
	TAILQ_INIT(&dead_list);

	lck_mtx_lock(&nstat_mtx);
	if (nstat_userland_udp_watchers != 0 ||
	    nstat_userland_tcp_watchers != 0 ||
	    nstat_userland_quic_watchers != 0) {
		nstat_control_state     *state;
		errno_t result;

		for (state = nstat_controls; state; state = state->ncs_next) {
			lck_mtx_lock(&state->ncs_mtx);
			TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
			{
				if (shad == (struct nstat_tu_shadow *)src->cookie) {
					nstat_provider_id_t provider_id = src->provider->nstat_provider_id;
					if (provider_id == NSTAT_PROVIDER_TCP_USERLAND ||
					    provider_id == NSTAT_PROVIDER_UDP_USERLAND ||
					    provider_id == NSTAT_PROVIDER_QUIC_USERLAND) {
						break;
					}
				}
			}

			if (src) {
				result = nstat_control_send_goodbye(state, src);

				TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
				TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
			}
			lck_mtx_unlock(&state->ncs_mtx);
		}
	}
	TAILQ_REMOVE(&nstat_userprot_shad_head, shad, shad_link);

	if (shad->shad_live) {
		if (shad->shad_provider == NSTAT_PROVIDER_TCP_USERLAND) {
			nstat_userland_tcp_shadows--;
		} else if (shad->shad_provider == NSTAT_PROVIDER_UDP_USERLAND) {
			nstat_userland_udp_shadows--;
		} else {
			nstat_userland_quic_shadows--;
		}
	}

	lck_mtx_unlock(&nstat_mtx);

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		nstat_control_cleanup_source(NULL, src, TRUE);
	}
	nstat_release_procdetails(shad->shad_procdetails);
	shad->shad_magic = TU_SHADOW_UNMAGIC;

	kfree_type(struct nstat_tu_shadow, shad);
}

static void
ntstat_userland_stats_event_locked(
	struct nstat_tu_shadow *shad,
	uint64_t event)
{
	nstat_control_state *state;
	nstat_src *src;
	errno_t result;
	nstat_provider_id_t provider_id;

	if (nstat_userland_udp_watchers != 0 || nstat_userland_tcp_watchers != 0 || nstat_userland_quic_watchers != 0) {
		for (state = nstat_controls; state; state = state->ncs_next) {
			if (((state->ncs_provider_filters[NSTAT_PROVIDER_TCP_USERLAND].npf_events & event) == 0) &&
			    ((state->ncs_provider_filters[NSTAT_PROVIDER_UDP_USERLAND].npf_events & event) == 0) &&
			    ((state->ncs_provider_filters[NSTAT_PROVIDER_QUIC_USERLAND].npf_events & event) == 0)) {
				continue;
			}
			lck_mtx_lock(&state->ncs_mtx);
			TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link) {
				provider_id = src->provider->nstat_provider_id;
				if (provider_id == NSTAT_PROVIDER_TCP_USERLAND || provider_id == NSTAT_PROVIDER_UDP_USERLAND ||
				    provider_id == NSTAT_PROVIDER_QUIC_USERLAND) {
					if (shad == (struct nstat_tu_shadow *)src->cookie) {
						break;
					}
				}
			}
			if (src && ((state->ncs_provider_filters[provider_id].npf_events & event) != 0)) {
				result = nstat_control_send_event(state, src, event);
			}
			lck_mtx_unlock(&state->ncs_mtx);
		}
	}
}

__private_extern__ void
ntstat_userland_stats_event(
	nstat_userland_context nstat_ctx,
	uint64_t event)
{
	// This will need refinement for when we do genuine stats filtering
	// See <rdar://problem/23022832> NetworkStatistics should provide opt-in notifications
	// For now it deals only with events that potentially cause any traditional netstat sources to be closed

	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)nstat_ctx;
	tailq_head_nstat_src dead_list;
	nstat_src *src;

	if (shad == NULL) {
		return;
	}

	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	if (event & NECP_CLIENT_STATISTICS_EVENT_TIME_WAIT) {
		TAILQ_INIT(&dead_list);

		lck_mtx_lock(&nstat_mtx);
		if (nstat_userland_udp_watchers != 0 ||
		    nstat_userland_tcp_watchers != 0 ||
		    nstat_userland_quic_watchers != 0) {
			nstat_control_state     *state;
			errno_t result;

			for (state = nstat_controls; state; state = state->ncs_next) {
				lck_mtx_lock(&state->ncs_mtx);
				TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
				{
					if (shad == (struct nstat_tu_shadow *)src->cookie) {
						break;
					}
				}

				if (src) {
					if (!(src->filter & NSTAT_FILTER_TCP_NO_EARLY_CLOSE)) {
						result = nstat_control_send_goodbye(state, src);

						TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
						TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
					}
				}
				lck_mtx_unlock(&state->ncs_mtx);
			}
		}
		lck_mtx_unlock(&nstat_mtx);

		while ((src = TAILQ_FIRST(&dead_list))) {
			TAILQ_REMOVE(&dead_list, src, ns_control_link);
			nstat_control_cleanup_source(NULL, src, TRUE);
		}
	}
}

__private_extern__ void
nstats_userland_stats_defunct_for_process(int pid)
{
	// Note that this can be called multiple times for the same process
	tailq_head_nstat_src dead_list;
	nstat_src *src, *tmpsrc;
	struct nstat_tu_shadow *shad;

	TAILQ_INIT(&dead_list);

	lck_mtx_lock(&nstat_mtx);

	if (nstat_userland_udp_watchers != 0 ||
	    nstat_userland_tcp_watchers != 0 ||
	    nstat_userland_quic_watchers != 0) {
		nstat_control_state     *state;
		errno_t result;

		for (state = nstat_controls; state; state = state->ncs_next) {
			lck_mtx_lock(&state->ncs_mtx);
			TAILQ_FOREACH_SAFE(src, &state->ncs_src_queue, ns_control_link, tmpsrc)
			{
				nstat_provider_id_t provider_id = src->provider->nstat_provider_id;
				if (provider_id == NSTAT_PROVIDER_TCP_USERLAND ||
				    provider_id == NSTAT_PROVIDER_UDP_USERLAND ||
				    provider_id == NSTAT_PROVIDER_QUIC_USERLAND) {
					shad = (struct nstat_tu_shadow *)src->cookie;
					if (shad->shad_procdetails->pdet_pid == pid) {
						result = nstat_control_send_goodbye(state, src);

						TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
						TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
					}
				}
			}
			lck_mtx_unlock(&state->ncs_mtx);
		}
	}

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if (shad->shad_live) {
			if (shad->shad_procdetails->pdet_pid == pid) {
				shad->shad_live = false;
				if (shad->shad_provider == NSTAT_PROVIDER_TCP_USERLAND) {
					nstat_userland_tcp_shadows--;
				} else if (shad->shad_provider == NSTAT_PROVIDER_UDP_USERLAND) {
					nstat_userland_udp_shadows--;
				} else {
					nstat_userland_quic_shadows--;
				}
			}
		}
	}

	lck_mtx_unlock(&nstat_mtx);

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		nstat_control_cleanup_source(NULL, src, TRUE);
	}
}

errno_t
nstat_userland_mark_rnf_override(uuid_t target_fuuid, bool rnf_override)
{
	// Note that this can be called multiple times for the same process
	struct nstat_tu_shadow *shad;
	uuid_t fuuid;
	errno_t result;

	lck_mtx_lock(&nstat_mtx);
	// We set the fallback state regardles of watchers as there may be future ones that need to know
	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);
		assert(shad->shad_procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);
		if (shad->shad_get_extension_fn(shad->shad_provider_context, NSTAT_EXTENDED_UPDATE_TYPE_FUUID, fuuid, sizeof(fuuid))) {
			if (uuid_compare(fuuid, target_fuuid) == 0) {
				break;
			}
		}
	}
	if (shad) {
		if (shad->shad_procdetails->pdet_pid != proc_selfpid()) {
			result = EPERM;
		} else {
			result = 0;
			// It would be possible but awkward to check the previous value
			// for RNF override, and send an event only if changed.
			// In practice it's fine to send an event regardless,
			// which "pushes" the last statistics for the previous mode
			shad->shad_rnf_override = rnf_override ? nstat_rnf_override_enabled
			    : nstat_rnf_override_disabled;
			ntstat_userland_stats_event_locked(shad,
			    rnf_override ? NSTAT_EVENT_SRC_ENTER_CELLFALLBACK
			    : NSTAT_EVENT_SRC_EXIT_CELLFALLBACK);
		}
	} else {
		result = EEXIST;
	}

	lck_mtx_unlock(&nstat_mtx);

	return result;
}

#pragma mark -- Generic Providers --

static nstat_provider   nstat_userland_conn_provider;
static nstat_provider   nstat_udp_subflow_provider;

static u_int32_t    nstat_generic_provider_watchers[NSTAT_PROVIDER_COUNT];

struct nstat_generic_shadow {
	tailq_entry_generic_shadow              gshad_link;
	nstat_provider_context                  gshad_provider_context;
	nstat_provider_request_vals_fn          *gshad_getvals_fn;
	nstat_provider_request_extensions_fn    *gshad_getextensions_fn;
	u_int64_t                               gshad_properties;
	u_int64_t                               gshad_start_timestamp;
	struct nstat_procdetails                *gshad_procdetails;
	nstat_provider_id_t                     gshad_provider;
	int32_t                                 gshad_refcnt;
	uint32_t                                gshad_magic;
};

// Magic number checking should remain in place until the userland provider has been fully proven
#define NSTAT_GENERIC_SHADOW_MAGIC             0xfadef00d
#define NSTAT_GENERIC_SHADOW_UNMAGIC           0xfadedead

static tailq_head_generic_shadow nstat_gshad_head = TAILQ_HEAD_INITIALIZER(nstat_gshad_head);

static inline void
nstat_retain_gshad(
	struct nstat_generic_shadow *gshad)
{
	assert(gshad->gshad_magic = NSTAT_GENERIC_SHADOW_MAGIC);

	OSIncrementAtomic(&gshad->gshad_refcnt);
}

static void
nstat_release_gshad(
	struct nstat_generic_shadow *gshad)
{
	assert(gshad->gshad_magic = NSTAT_GENERIC_SHADOW_MAGIC);

	if (OSDecrementAtomic(&gshad->gshad_refcnt) == 1) {
		nstat_release_procdetails(gshad->gshad_procdetails);
		gshad->gshad_magic = NSTAT_GENERIC_SHADOW_UNMAGIC;
		kfree_type(struct nstat_generic_shadow, gshad);
	}
}

static errno_t
nstat_generic_provider_lookup(
	__unused const void                 *data,
	__unused u_int32_t                  length,
	__unused nstat_provider_cookie_t    *out_cookie)
{
	// Looking up a specific connection is not supported
	return ENOTSUP;
}

static int
nstat_generic_provider_gone(
	__unused nstat_provider_cookie_t    cookie)
{
	// Returns non-zero if the source has gone.
	// We don't keep a source hanging around, so the answer is always 0
	return 0;
}

static errno_t
nstat_generic_provider_counts(
	nstat_provider_cookie_t cookie,
	struct nstat_counts     *out_counts,
	int                     *out_gone)
{
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)cookie;
	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	memset(out_counts, 0, sizeof(*out_counts));

	bool result = (*gshad->gshad_getvals_fn)(gshad->gshad_provider_context, NULL, out_counts, NULL);

	if (out_gone) {
		*out_gone = 0;
	}
	return (result)? 0 : EIO;
}


static errno_t
nstat_generic_provider_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *data,
	__unused size_t         len)
{
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)cookie;
	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);
	struct nstat_procdetails *procdetails = gshad->gshad_procdetails;
	assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

	bool result = (*gshad->gshad_getvals_fn)(gshad->gshad_provider_context, NULL, NULL, data);

	switch (gshad->gshad_provider) {
	case NSTAT_PROVIDER_CONN_USERLAND:
	{
		nstat_connection_descriptor *desc = (nstat_connection_descriptor *)data;
		desc->pid = procdetails->pdet_pid;
		desc->upid = procdetails->pdet_upid;
		uuid_copy(desc->uuid, procdetails->pdet_uuid);
		strlcpy(desc->pname, procdetails->pdet_procname, sizeof(desc->pname));
		desc->start_timestamp = gshad->gshad_start_timestamp;
		desc->timestamp = mach_continuous_time();
		break;
	}
	case NSTAT_PROVIDER_UDP_SUBFLOW:
	{
		nstat_udp_descriptor *desc = (nstat_udp_descriptor *)data;
		desc->pid = procdetails->pdet_pid;
		desc->upid = procdetails->pdet_upid;
		uuid_copy(desc->uuid, procdetails->pdet_uuid);
		strlcpy(desc->pname, procdetails->pdet_procname, sizeof(desc->pname));
		desc->start_timestamp = gshad->gshad_start_timestamp;
		desc->timestamp = mach_continuous_time();
		break;
	}
	default:
		break;
	}
	return (result)? 0 : EIO;
}

static void
nstat_generic_provider_release(
	__unused nstat_provider_cookie_t    cookie,
	__unused int locked)
{
	// Called when a nstat_src is detached.
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)cookie;

	nstat_release_gshad(gshad);
}

static bool
nstat_generic_provider_reporting_allowed(
	nstat_provider_cookie_t cookie,
	nstat_provider_filter *filter,
	u_int64_t suppression_flags)
{
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)cookie;

	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	if ((filter->npf_flags & NSTAT_FILTER_SUPPRESS_BORING_FLAGS) != 0) {
		if ((filter->npf_flags & suppression_flags) != 0) {
			return false;
		}
	}

	// Filter based on interface and connection flags
	// If a provider doesn't support flags, a client shouldn't attempt to use filtering
	if ((filter->npf_flags & NSTAT_FILTER_IFNET_AND_CONN_FLAGS) != 0) {
		u_int32_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*gshad->gshad_getvals_fn)(gshad->gshad_provider_context, &ifflags, NULL, NULL)) {
			if ((filter->npf_flags & ifflags) == 0) {
				return false;
			}
		}
	}

	if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) {
		struct nstat_procdetails *procdetails = gshad->gshad_procdetails;
		assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

		// Check details that we have readily to hand before asking the provider for descriptor items
		if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_PID) != 0) &&
		    (filter->npf_pid == procdetails->pdet_pid)) {
			return true;
		}
		if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_UUID) != 0) &&
		    (memcmp(filter->npf_uuid, &procdetails->pdet_uuid, sizeof(filter->npf_uuid)) == 0)) {
			return true;
		}
		if ((filter->npf_flags & (NSTAT_FILTER_SPECIFIC_USER_BY_EPID | NSTAT_FILTER_SPECIFIC_USER_BY_EUUID)) != 0) {
			nstat_udp_descriptor udp_desc;  // Stack allocation - OK or pushing the limits too far?
			switch (gshad->gshad_provider) {
			case NSTAT_PROVIDER_CONN_USERLAND:
				// Filtering by effective uuid or effective pid is currently not supported
				filter->npf_flags &= ~((uint64_t)(NSTAT_FILTER_SPECIFIC_USER_BY_EPID | NSTAT_FILTER_SPECIFIC_USER_BY_EUUID));
				printf("%s - attempt to filter conn provider by effective pid/uuid, not supported\n", __func__);
				return true;

			case NSTAT_PROVIDER_UDP_SUBFLOW:
				if ((*gshad->gshad_getvals_fn)(gshad->gshad_provider_context, NULL, NULL, &udp_desc)) {
					if (check_reporting_for_user(filter, procdetails->pdet_pid, (pid_t)udp_desc.epid,
					    &procdetails->pdet_uuid, &udp_desc.euuid)) {
						return true;
					}
				}
				break;
			default:
				break;
			}
		}
		return false;
	}
	return true;
}

static size_t
nstat_generic_extensions(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *buf, size_t len)
{
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)cookie;
	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);
	assert(gshad->gshad_procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

	if (gshad->gshad_getextensions_fn == NULL) {
		return 0;
	}
	return gshad->gshad_getextensions_fn(gshad->gshad_provider_context, extension_id, buf, len);
}

static errno_t
nstat_generic_provider_add_watcher(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs  *req)
{
	errno_t result;
	nstat_provider_id_t  provider_id = req->provider;
	nstat_provider *provider;

	switch (provider_id) {
	case NSTAT_PROVIDER_CONN_USERLAND:
		provider = &nstat_userland_conn_provider;
		break;
	case NSTAT_PROVIDER_UDP_SUBFLOW:
		provider = &nstat_udp_subflow_provider;
		break;
	default:
		return ENOTSUP;
	}

	lck_mtx_lock(&nstat_mtx);
	result = nstat_set_provider_filter(state, req);

	if (result == 0) {
		struct nstat_generic_shadow *gshad;
		nstat_provider_filter *filter = &state->ncs_provider_filters[provider_id];

		OSIncrementAtomic(&nstat_generic_provider_watchers[provider_id]);

		TAILQ_FOREACH(gshad, &nstat_gshad_head, gshad_link) {
			assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

			if (gshad->gshad_provider == provider_id) {
				if (filter->npf_flags & NSTAT_FILTER_INITIAL_PROPERTIES) {
					u_int64_t npf_flags = filter->npf_flags & NSTAT_FILTER_IFNET_AND_CONN_FLAGS;
					if ((npf_flags != 0) && ((npf_flags & gshad->gshad_properties) == 0)) {
						// Skip this one
						// Note - no filtering by pid or UUID supported at this point, for simplicity
						continue;
					}
				}
				nstat_retain_gshad(gshad);
				result = nstat_control_source_add(0, state, provider, gshad);
				if (result != 0) {
					printf("%s - nstat_control_source_add returned %d for "
					    "provider type: %d\n", __func__, result, provider_id);
					nstat_release_gshad(gshad);
					break;
				}
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return result;
}

static void
nstat_userland_conn_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_generic_provider_watchers[NSTAT_PROVIDER_CONN_USERLAND]);
}

static void
nstat_udp_subflow_remove_watcher(
	__unused nstat_control_state    *state)
{
	OSDecrementAtomic(&nstat_generic_provider_watchers[NSTAT_PROVIDER_UDP_SUBFLOW]);
}

static void
nstat_init_userland_conn_provider(void)
{
	bzero(&nstat_userland_conn_provider, sizeof(nstat_userland_conn_provider));
	nstat_userland_conn_provider.nstat_descriptor_length = sizeof(nstat_connection_descriptor);
	nstat_userland_conn_provider.nstat_provider_id = NSTAT_PROVIDER_CONN_USERLAND;
	nstat_userland_conn_provider.nstat_lookup = nstat_generic_provider_lookup;
	nstat_userland_conn_provider.nstat_gone = nstat_generic_provider_gone;
	nstat_userland_conn_provider.nstat_counts = nstat_generic_provider_counts;
	nstat_userland_conn_provider.nstat_release = nstat_generic_provider_release;
	nstat_userland_conn_provider.nstat_watcher_add = nstat_generic_provider_add_watcher;
	nstat_userland_conn_provider.nstat_watcher_remove = nstat_userland_conn_remove_watcher;
	nstat_userland_conn_provider.nstat_copy_descriptor = nstat_generic_provider_copy_descriptor;
	nstat_userland_conn_provider.nstat_reporting_allowed = nstat_generic_provider_reporting_allowed;
	nstat_userland_conn_provider.nstat_copy_extension = nstat_generic_extensions;
	nstat_userland_conn_provider.next = nstat_providers;
	nstat_providers = &nstat_userland_conn_provider;
}

static void
nstat_init_udp_subflow_provider(void)
{
	bzero(&nstat_udp_subflow_provider, sizeof(nstat_udp_subflow_provider));
	nstat_udp_subflow_provider.nstat_descriptor_length = sizeof(nstat_udp_descriptor);
	nstat_udp_subflow_provider.nstat_provider_id = NSTAT_PROVIDER_UDP_SUBFLOW;
	nstat_udp_subflow_provider.nstat_lookup = nstat_generic_provider_lookup;
	nstat_udp_subflow_provider.nstat_gone = nstat_generic_provider_gone;
	nstat_udp_subflow_provider.nstat_counts = nstat_generic_provider_counts;
	nstat_udp_subflow_provider.nstat_release = nstat_generic_provider_release;
	nstat_udp_subflow_provider.nstat_watcher_add = nstat_generic_provider_add_watcher;
	nstat_udp_subflow_provider.nstat_watcher_remove = nstat_udp_subflow_remove_watcher;
	nstat_udp_subflow_provider.nstat_copy_descriptor = nstat_generic_provider_copy_descriptor;
	nstat_udp_subflow_provider.nstat_reporting_allowed = nstat_generic_provider_reporting_allowed;
	nstat_udp_subflow_provider.nstat_copy_extension = nstat_generic_extensions;
	nstat_udp_subflow_provider.next = nstat_providers;
	nstat_providers = &nstat_udp_subflow_provider;
}

// Things get started with a call from the provider to netstats to say that there’s a new source
__private_extern__ nstat_context
nstat_provider_stats_open(nstat_provider_context ctx,
    int provider_id,
    u_int64_t properties,
    nstat_provider_request_vals_fn req_fn,
    nstat_provider_request_extensions_fn req_extensions_fn)
{
	struct nstat_generic_shadow *gshad;
	struct nstat_procdetails *procdetails;
	nstat_provider *provider = nstat_find_provider_by_id(provider_id);

	gshad = kalloc_type(struct nstat_generic_shadow, Z_WAITOK | Z_NOFAIL);

	procdetails = nstat_retain_curprocdetails();

	if (procdetails == NULL) {
		kfree_type(struct nstat_generic_shadow, gshad);
		return NULL;
	}

	gshad->gshad_getvals_fn         = req_fn;
	gshad->gshad_getextensions_fn   = req_extensions_fn;
	gshad->gshad_provider_context   = ctx;
	gshad->gshad_properties         = properties;
	gshad->gshad_procdetails        = procdetails;
	gshad->gshad_provider           = provider_id;
	gshad->gshad_start_timestamp    = mach_continuous_time();
	gshad->gshad_refcnt             = 0;
	gshad->gshad_magic              = NSTAT_GENERIC_SHADOW_MAGIC;
	nstat_retain_gshad(gshad);

	lck_mtx_lock(&nstat_mtx);
	nstat_control_state     *state;

	// Even if there are no watchers, we save the shadow structure
	TAILQ_INSERT_HEAD(&nstat_gshad_head, gshad, gshad_link);

	for (state = nstat_controls; state; state = state->ncs_next) {
		if ((state->ncs_watching & (1 << provider_id)) != 0) {
			// Does this client want an initial filtering to be made?
			u_int64_t npf_flags = state->ncs_provider_filters[provider->nstat_provider_id].npf_flags;
			if (npf_flags & NSTAT_FILTER_INITIAL_PROPERTIES) {
				npf_flags &= NSTAT_FILTER_IFNET_AND_CONN_FLAGS;
				if ((npf_flags != 0) && ((npf_flags & properties) == 0)) {
					// Skip this one
					// Note - no filtering by pid or UUID supported at this point, for simplicity
					continue;
				}
			}
			// this client is watching, so link to it.
			nstat_retain_gshad(gshad);
			int result = nstat_control_source_add(0, state, provider, gshad);
			if (result != 0) {
				// There should be some kind of statistics for failures like this.
				// <rdar://problem/31377195> The kernel ntstat component should keep some
				// internal counters reflecting operational state for eventual AWD reporting
				nstat_release_gshad(gshad);
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return (nstat_context) gshad;
}


// When the source is closed, netstats will make one last call on the request functions to retrieve final values
__private_extern__ void
nstat_provider_stats_close(nstat_context nstat_ctx)
{
	tailq_head_nstat_src dead_list;
	nstat_src *src;
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)nstat_ctx;

	if (gshad == NULL) {
		printf("%s - called with null reference", __func__);
		return;
	}

	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	if (gshad->gshad_magic != NSTAT_GENERIC_SHADOW_MAGIC) {
		printf("%s - called with incorrect shadow magic 0x%x", __func__, gshad->gshad_magic);
	}

	TAILQ_INIT(&dead_list);

	lck_mtx_lock(&nstat_mtx);

	TAILQ_REMOVE(&nstat_gshad_head, gshad, gshad_link);

	int32_t num_srcs = gshad->gshad_refcnt - 1;
	if ((nstat_generic_provider_watchers[gshad->gshad_provider] != 0) && (num_srcs > 0)) {
		nstat_control_state     *state;
		errno_t result;

		for (state = nstat_controls; state; state = state->ncs_next) {
			// Only scan further if this client is watching
			if ((state->ncs_watching & (1 << gshad->gshad_provider)) != 0) {
				lck_mtx_lock(&state->ncs_mtx);
				TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
				{
					if ((gshad == (struct nstat_generic_shadow *)src->cookie) &&
					    (gshad->gshad_provider == src->provider->nstat_provider_id)) {
						break;
					}
				}
				if (src) {
					result = nstat_control_send_goodbye(state, src);
					// There is currently no recovery possible from failure to send,
					// so no need to check the return code.
					// rdar://28312774 (Scalability and resilience issues in ntstat.c)

					TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
					TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
					--num_srcs;
				}
				lck_mtx_unlock(&state->ncs_mtx);

				// Performance optimization, don't scan full lists if no chance of presence
				if (num_srcs == 0) {
					break;
				}
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		nstat_control_cleanup_source(NULL, src, TRUE);
	}
	nstat_release_gshad(gshad);
}

// Events that cause a significant change may be reported via a flags word
void
nstat_provider_stats_event(__unused nstat_context nstat_ctx, __unused uint64_t event)
{
	nstat_src *src;
	struct nstat_generic_shadow *gshad = (struct nstat_generic_shadow *)nstat_ctx;

	if (gshad == NULL) {
		printf("%s - called with null reference", __func__);
		return;
	}

	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	if (gshad->gshad_magic != NSTAT_GENERIC_SHADOW_MAGIC) {
		printf("%s - called with incorrect shadow magic 0x%x", __func__, gshad->gshad_magic);
	}

	lck_mtx_lock(&nstat_mtx);

	if (nstat_generic_provider_watchers[gshad->gshad_provider] != 0) {
		nstat_control_state     *state;
		errno_t result;
		nstat_provider_id_t provider_id = gshad->gshad_provider;

		for (state = nstat_controls; state; state = state->ncs_next) {
			// Only scan further if this client is watching and has interest in the event
			// or the client has requested "boring" unchanged status to be ignored
			if (((state->ncs_watching & (1 << provider_id)) != 0) &&
			    (((state->ncs_provider_filters[provider_id].npf_events & event) != 0) ||
			    ((state->ncs_provider_filters[provider_id].npf_flags & NSTAT_FILTER_SUPPRESS_BORING_FLAGS) != 0))) {
				lck_mtx_lock(&state->ncs_mtx);
				TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
				{
					if (gshad == (struct nstat_generic_shadow *)src->cookie) {
						break;
					}
				}

				if (src) {
					src->ns_reported = false;
					if ((state->ncs_provider_filters[provider_id].npf_events & event) != 0) {
						result = nstat_control_send_event(state, src, event);
						// There is currently no recovery possible from failure to send,
						// so no need to check the return code.
						// rdar://28312774 (Scalability and resilience issues in ntstat.c)
					}
				}
				lck_mtx_unlock(&state->ncs_mtx);
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
}

#endif /* SKYWALK */


#pragma mark -- ifnet Provider --

static nstat_provider   nstat_ifnet_provider;

/*
 * We store a pointer to the ifnet and the original threshold
 * requested by the client.
 */
struct nstat_ifnet_cookie {
	struct ifnet    *ifp;
	uint64_t        threshold;
};

static errno_t
nstat_ifnet_lookup(
	const void              *data,
	u_int32_t               length,
	nstat_provider_cookie_t *out_cookie)
{
	const nstat_ifnet_add_param *param = (const nstat_ifnet_add_param *)data;
	struct ifnet *ifp;
	boolean_t changed = FALSE;
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_ifnet_cookie *cookie;

	if (length < sizeof(*param) || param->threshold < 1024 * 1024) {
		return EINVAL;
	}
	if (nstat_privcheck != 0) {
		errno_t result = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);
		if (result != 0) {
			return result;
		}
	}
	cookie = kalloc_type(struct nstat_ifnet_cookie,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
	{
		if (!ifnet_is_attached(ifp, 1)) {
			continue;
		}
		ifnet_lock_exclusive(ifp);
		if (ifp->if_index == param->ifindex) {
			cookie->ifp = ifp;
			cookie->threshold = param->threshold;
			*out_cookie = cookie;
			if (!ifp->if_data_threshold ||
			    ifp->if_data_threshold > param->threshold) {
				changed = TRUE;
				ifp->if_data_threshold = param->threshold;
			}
			ifnet_lock_done(ifp);
			ifnet_reference(ifp);
			ifnet_decr_iorefcnt(ifp);
			break;
		}
		ifnet_lock_done(ifp);
		ifnet_decr_iorefcnt(ifp);
	}
	ifnet_head_done();

	/*
	 * When we change the threshold to something smaller, we notify
	 * all of our clients with a description message.
	 * We won't send a message to the client we are currently serving
	 * because it has no `ifnet source' yet.
	 */
	if (changed) {
		lck_mtx_lock(&nstat_mtx);
		for (state = nstat_controls; state; state = state->ncs_next) {
			lck_mtx_lock(&state->ncs_mtx);
			TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
			{
				if (src->provider != &nstat_ifnet_provider) {
					continue;
				}
				nstat_control_send_description(state, src, 0, 0);
			}
			lck_mtx_unlock(&state->ncs_mtx);
		}
		lck_mtx_unlock(&nstat_mtx);
	}
	if (cookie->ifp == NULL) {
		kfree_type(struct nstat_ifnet_cookie, cookie);
	}

	return ifp ? 0 : EINVAL;
}

static int
nstat_ifnet_gone(
	nstat_provider_cookie_t cookie)
{
	struct ifnet *ifp;
	struct nstat_ifnet_cookie *ifcookie =
	    (struct nstat_ifnet_cookie *)cookie;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
	{
		if (ifp == ifcookie->ifp) {
			break;
		}
	}
	ifnet_head_done();

	return ifp ? 0 : 1;
}

static errno_t
nstat_ifnet_counts(
	nstat_provider_cookie_t cookie,
	struct nstat_counts     *out_counts,
	int                     *out_gone)
{
	struct nstat_ifnet_cookie *ifcookie =
	    (struct nstat_ifnet_cookie *)cookie;
	struct ifnet *ifp = ifcookie->ifp;

	if (out_gone) {
		*out_gone = 0;
	}

	// if the ifnet is gone, we should stop using it
	if (nstat_ifnet_gone(cookie)) {
		if (out_gone) {
			*out_gone = 1;
		}
		return EINVAL;
	}

	bzero(out_counts, sizeof(*out_counts));
	out_counts->nstat_rxpackets = ifp->if_ipackets;
	out_counts->nstat_rxbytes = ifp->if_ibytes;
	out_counts->nstat_txpackets = ifp->if_opackets;
	out_counts->nstat_txbytes = ifp->if_obytes;
	out_counts->nstat_cell_rxbytes = out_counts->nstat_cell_txbytes = 0;
	return 0;
}

static void
nstat_ifnet_release(
	nstat_provider_cookie_t cookie,
	__unused int            locked)
{
	struct nstat_ifnet_cookie *ifcookie;
	struct ifnet *ifp;
	nstat_control_state *state;
	nstat_src *src;
	uint64_t minthreshold = UINT64_MAX;

	/*
	 * Find all the clients that requested a threshold
	 * for this ifnet and re-calculate if_data_threshold.
	 */
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->ncs_mtx);
		TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
		{
			/* Skip the provider we are about to detach. */
			if (src->provider != &nstat_ifnet_provider ||
			    src->cookie == cookie) {
				continue;
			}
			ifcookie = (struct nstat_ifnet_cookie *)src->cookie;
			if (ifcookie->threshold < minthreshold) {
				minthreshold = ifcookie->threshold;
			}
		}
		lck_mtx_unlock(&state->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
	/*
	 * Reset if_data_threshold or disable it.
	 */
	ifcookie = (struct nstat_ifnet_cookie *)cookie;
	ifp = ifcookie->ifp;
	if (ifnet_is_attached(ifp, 1)) {
		ifnet_lock_exclusive(ifp);
		if (minthreshold == UINT64_MAX) {
			ifp->if_data_threshold = 0;
		} else {
			ifp->if_data_threshold = minthreshold;
		}
		ifnet_lock_done(ifp);
		ifnet_decr_iorefcnt(ifp);
	}
	ifnet_release(ifp);
	kfree_type(struct nstat_ifnet_cookie, ifcookie);
}

static void
nstat_ifnet_copy_link_status(
	struct ifnet                    *ifp,
	struct nstat_ifnet_descriptor   *desc)
{
	struct if_link_status *ifsr = ifp->if_link_status;
	nstat_ifnet_desc_link_status *link_status = &desc->link_status;

	link_status->link_status_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_NONE;
	if (ifsr == NULL) {
		return;
	}

	lck_rw_lock_shared(&ifp->if_link_status_lock);

	if (ifp->if_type == IFT_CELLULAR) {
		nstat_ifnet_desc_cellular_status *cell_status = &link_status->u.cellular;
		struct if_cellular_status_v1 *if_cell_sr =
		    &ifsr->ifsr_u.ifsr_cell.if_cell_u.if_status_v1;

		if (ifsr->ifsr_version != IF_CELLULAR_STATUS_REPORT_VERSION_1) {
			goto done;
		}

		link_status->link_status_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_CELLULAR;

		if (if_cell_sr->valid_bitmask & IF_CELL_LINK_QUALITY_METRIC_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_LINK_QUALITY_METRIC_VALID;
			cell_status->link_quality_metric = if_cell_sr->link_quality_metric;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_EFFECTIVE_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_EFFECTIVE_BANDWIDTH_VALID;
			cell_status->ul_effective_bandwidth = if_cell_sr->ul_effective_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MAX_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MAX_BANDWIDTH_VALID;
			cell_status->ul_max_bandwidth = if_cell_sr->ul_max_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MIN_LATENCY_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MIN_LATENCY_VALID;
			cell_status->ul_min_latency = if_cell_sr->ul_min_latency;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_EFFECTIVE_LATENCY_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_EFFECTIVE_LATENCY_VALID;
			cell_status->ul_effective_latency = if_cell_sr->ul_effective_latency;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MAX_LATENCY_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MAX_LATENCY_VALID;
			cell_status->ul_max_latency = if_cell_sr->ul_max_latency;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_RETXT_LEVEL_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_VALID;
			if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_NONE) {
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_NONE;
			} else if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_LOW) {
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_LOW;
			} else if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_MEDIUM) {
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_MEDIUM;
			} else if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_HIGH) {
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_HIGH;
			} else {
				cell_status->valid_bitmask &= ~NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_VALID;
			}
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_BYTES_LOST_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_BYTES_LOST_VALID;
			cell_status->ul_bytes_lost = if_cell_sr->ul_bytes_lost;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MIN_QUEUE_SIZE_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MIN_QUEUE_SIZE_VALID;
			cell_status->ul_min_queue_size = if_cell_sr->ul_min_queue_size;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_AVG_QUEUE_SIZE_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_AVG_QUEUE_SIZE_VALID;
			cell_status->ul_avg_queue_size = if_cell_sr->ul_avg_queue_size;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MAX_QUEUE_SIZE_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MAX_QUEUE_SIZE_VALID;
			cell_status->ul_max_queue_size = if_cell_sr->ul_max_queue_size;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_DL_EFFECTIVE_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_DL_EFFECTIVE_BANDWIDTH_VALID;
			cell_status->dl_effective_bandwidth = if_cell_sr->dl_effective_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_DL_MAX_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_DL_MAX_BANDWIDTH_VALID;
			cell_status->dl_max_bandwidth = if_cell_sr->dl_max_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_CONFIG_INACTIVITY_TIME_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_CONFIG_INACTIVITY_TIME_VALID;
			cell_status->config_inactivity_time = if_cell_sr->config_inactivity_time;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_CONFIG_BACKOFF_TIME_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_CONFIG_BACKOFF_TIME_VALID;
			cell_status->config_backoff_time = if_cell_sr->config_backoff_time;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MSS_RECOMMENDED_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_MSS_RECOMMENDED_VALID;
			cell_status->mss_recommended = if_cell_sr->mss_recommended;
		}
	} else if (IFNET_IS_WIFI(ifp)) {
		nstat_ifnet_desc_wifi_status *wifi_status = &link_status->u.wifi;
		struct if_wifi_status_v1 *if_wifi_sr =
		    &ifsr->ifsr_u.ifsr_wifi.if_wifi_u.if_status_v1;

		if (ifsr->ifsr_version != IF_WIFI_STATUS_REPORT_VERSION_1) {
			goto done;
		}

		link_status->link_status_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_WIFI;

		if (if_wifi_sr->valid_bitmask & IF_WIFI_LINK_QUALITY_METRIC_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_LINK_QUALITY_METRIC_VALID;
			wifi_status->link_quality_metric = if_wifi_sr->link_quality_metric;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID;
			wifi_status->ul_effective_bandwidth = if_wifi_sr->ul_effective_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_MAX_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_MAX_BANDWIDTH_VALID;
			wifi_status->ul_max_bandwidth = if_wifi_sr->ul_max_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_MIN_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_MIN_LATENCY_VALID;
			wifi_status->ul_min_latency = if_wifi_sr->ul_min_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_EFFECTIVE_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_EFFECTIVE_LATENCY_VALID;
			wifi_status->ul_effective_latency = if_wifi_sr->ul_effective_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_MAX_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_MAX_LATENCY_VALID;
			wifi_status->ul_max_latency = if_wifi_sr->ul_max_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_RETXT_LEVEL_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_VALID;
			if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_NONE) {
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_NONE;
			} else if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_LOW) {
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_LOW;
			} else if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_MEDIUM) {
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_MEDIUM;
			} else if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_HIGH) {
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_HIGH;
			} else {
				wifi_status->valid_bitmask &= ~NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_VALID;
			}
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_BYTES_LOST_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_BYTES_LOST_VALID;
			wifi_status->ul_bytes_lost = if_wifi_sr->ul_bytes_lost;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_ERROR_RATE_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_ERROR_RATE_VALID;
			wifi_status->ul_error_rate = if_wifi_sr->ul_error_rate;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID;
			wifi_status->dl_effective_bandwidth = if_wifi_sr->dl_effective_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_MAX_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_MAX_BANDWIDTH_VALID;
			wifi_status->dl_max_bandwidth = if_wifi_sr->dl_max_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_MIN_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_MIN_LATENCY_VALID;
			wifi_status->dl_min_latency = if_wifi_sr->dl_min_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_EFFECTIVE_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_EFFECTIVE_LATENCY_VALID;
			wifi_status->dl_effective_latency = if_wifi_sr->dl_effective_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_MAX_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_MAX_LATENCY_VALID;
			wifi_status->dl_max_latency = if_wifi_sr->dl_max_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_ERROR_RATE_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_ERROR_RATE_VALID;
			wifi_status->dl_error_rate = if_wifi_sr->dl_error_rate;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_FREQUENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_VALID;
			if (if_wifi_sr->config_frequency == IF_WIFI_CONFIG_FREQUENCY_2_4_GHZ) {
				wifi_status->config_frequency = NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_2_4_GHZ;
			} else if (if_wifi_sr->config_frequency == IF_WIFI_CONFIG_FREQUENCY_5_0_GHZ) {
				wifi_status->config_frequency = NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_5_0_GHZ;
			} else {
				wifi_status->valid_bitmask &= ~NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_VALID;
			}
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_MULTICAST_RATE_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_MULTICAST_RATE_VALID;
			wifi_status->config_multicast_rate = if_wifi_sr->config_multicast_rate;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_SCAN_COUNT_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_SCAN_COUNT_VALID;
			wifi_status->scan_count = if_wifi_sr->scan_count;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_SCAN_DURATION_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_SCAN_DURATION_VALID;
			wifi_status->scan_duration = if_wifi_sr->scan_duration;
		}
	}

done:
	lck_rw_done(&ifp->if_link_status_lock);
}

static u_int64_t nstat_ifnet_last_report_time = 0;
extern int tcp_report_stats_interval;

static void
nstat_ifnet_compute_percentages(struct if_tcp_ecn_perf_stat *ifst)
{
	/* Retransmit percentage */
	if (ifst->total_rxmitpkts > 0 && ifst->total_txpkts > 0) {
		/* shift by 10 for precision */
		ifst->rxmit_percent =
		    ((ifst->total_rxmitpkts << 10) * 100) / ifst->total_txpkts;
	} else {
		ifst->rxmit_percent = 0;
	}

	/* Out-of-order percentage */
	if (ifst->total_oopkts > 0 && ifst->total_rxpkts > 0) {
		/* shift by 10 for precision */
		ifst->oo_percent =
		    ((ifst->total_oopkts << 10) * 100) / ifst->total_rxpkts;
	} else {
		ifst->oo_percent = 0;
	}

	/* Reorder percentage */
	if (ifst->total_reorderpkts > 0 &&
	    (ifst->total_txpkts + ifst->total_rxpkts) > 0) {
		/* shift by 10 for precision */
		ifst->reorder_percent =
		    ((ifst->total_reorderpkts << 10) * 100) /
		    (ifst->total_txpkts + ifst->total_rxpkts);
	} else {
		ifst->reorder_percent = 0;
	}
}

static void
nstat_ifnet_normalize_counter(struct if_tcp_ecn_stat *if_st)
{
	u_int64_t ecn_on_conn, ecn_off_conn;

	if (if_st == NULL) {
		return;
	}
	ecn_on_conn = if_st->ecn_client_success +
	    if_st->ecn_server_success;
	ecn_off_conn = if_st->ecn_off_conn +
	    (if_st->ecn_client_setup - if_st->ecn_client_success) +
	    (if_st->ecn_server_setup - if_st->ecn_server_success);

	/*
	 * report sack episodes, rst_drop and rxmit_drop
	 *  as a ratio per connection, shift by 10 for precision
	 */
	if (ecn_on_conn > 0) {
		if_st->ecn_on.sack_episodes =
		    (if_st->ecn_on.sack_episodes << 10) / ecn_on_conn;
		if_st->ecn_on.rst_drop =
		    (if_st->ecn_on.rst_drop << 10) * 100 / ecn_on_conn;
		if_st->ecn_on.rxmit_drop =
		    (if_st->ecn_on.rxmit_drop << 10) * 100 / ecn_on_conn;
	} else {
		/* set to zero, just in case */
		if_st->ecn_on.sack_episodes = 0;
		if_st->ecn_on.rst_drop = 0;
		if_st->ecn_on.rxmit_drop = 0;
	}

	if (ecn_off_conn > 0) {
		if_st->ecn_off.sack_episodes =
		    (if_st->ecn_off.sack_episodes << 10) / ecn_off_conn;
		if_st->ecn_off.rst_drop =
		    (if_st->ecn_off.rst_drop << 10) * 100 / ecn_off_conn;
		if_st->ecn_off.rxmit_drop =
		    (if_st->ecn_off.rxmit_drop << 10) * 100 / ecn_off_conn;
	} else {
		if_st->ecn_off.sack_episodes = 0;
		if_st->ecn_off.rst_drop = 0;
		if_st->ecn_off.rxmit_drop = 0;
	}
	if_st->ecn_total_conn = ecn_off_conn + ecn_on_conn;
}

static void
nstat_ifnet_report_ecn_stats(void)
{
	u_int64_t uptime, last_report_time;
	struct nstat_sysinfo_data data;
	struct nstat_sysinfo_ifnet_ecn_stats *st;
	struct ifnet *ifp;

	uptime = net_uptime();

	if ((int)(uptime - nstat_ifnet_last_report_time) <
	    tcp_report_stats_interval) {
		return;
	}

	last_report_time = nstat_ifnet_last_report_time;
	nstat_ifnet_last_report_time = uptime;
	data.flags = NSTAT_SYSINFO_IFNET_ECN_STATS;
	st = &data.u.ifnet_ecn_stats;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (ifp->if_ipv4_stat == NULL || ifp->if_ipv6_stat == NULL) {
			continue;
		}

		if (!IF_FULLY_ATTACHED(ifp)) {
			continue;
		}

		/* Limit reporting to Wifi, Ethernet and cellular. */
		if (!(IFNET_IS_ETHERNET(ifp) || IFNET_IS_CELLULAR(ifp))) {
			continue;
		}

		bzero(st, sizeof(*st));
		if (IFNET_IS_CELLULAR(ifp)) {
			st->ifnet_type = NSTAT_IFNET_ECN_TYPE_CELLULAR;
		} else if (IFNET_IS_WIFI(ifp)) {
			st->ifnet_type = NSTAT_IFNET_ECN_TYPE_WIFI;
		} else {
			st->ifnet_type = NSTAT_IFNET_ECN_TYPE_ETHERNET;
		}
		data.unsent_data_cnt = ifp->if_unsent_data_cnt;
		/* skip if there was no update since last report */
		if (ifp->if_ipv4_stat->timestamp <= 0 ||
		    ifp->if_ipv4_stat->timestamp < last_report_time) {
			goto v6;
		}
		st->ifnet_proto = NSTAT_IFNET_ECN_PROTO_IPV4;
		/* compute percentages using packet counts */
		nstat_ifnet_compute_percentages(&ifp->if_ipv4_stat->ecn_on);
		nstat_ifnet_compute_percentages(&ifp->if_ipv4_stat->ecn_off);
		nstat_ifnet_normalize_counter(ifp->if_ipv4_stat);
		bcopy(ifp->if_ipv4_stat, &st->ecn_stat,
		    sizeof(st->ecn_stat));
		nstat_sysinfo_send_data(&data);
		bzero(ifp->if_ipv4_stat, sizeof(*ifp->if_ipv4_stat));

v6:
		/* skip if there was no update since last report */
		if (ifp->if_ipv6_stat->timestamp <= 0 ||
		    ifp->if_ipv6_stat->timestamp < last_report_time) {
			continue;
		}
		st->ifnet_proto = NSTAT_IFNET_ECN_PROTO_IPV6;

		/* compute percentages using packet counts */
		nstat_ifnet_compute_percentages(&ifp->if_ipv6_stat->ecn_on);
		nstat_ifnet_compute_percentages(&ifp->if_ipv6_stat->ecn_off);
		nstat_ifnet_normalize_counter(ifp->if_ipv6_stat);
		bcopy(ifp->if_ipv6_stat, &st->ecn_stat,
		    sizeof(st->ecn_stat));
		nstat_sysinfo_send_data(&data);

		/* Zero the stats in ifp */
		bzero(ifp->if_ipv6_stat, sizeof(*ifp->if_ipv6_stat));
	}
	ifnet_head_done();
}

/* Some thresholds to determine Low Iternet mode */
#define NSTAT_LIM_DL_MAX_BANDWIDTH_THRESHOLD    1000000 /* 1 Mbps */
#define NSTAT_LIM_UL_MAX_BANDWIDTH_THRESHOLD    500000  /* 500 Kbps */
#define NSTAT_LIM_UL_MIN_RTT_THRESHOLD          1000    /* 1 second */
#define NSTAT_LIM_CONN_TIMEOUT_PERCENT_THRESHOLD (10 << 10) /* 10 percent connection timeouts */
#define NSTAT_LIM_PACKET_LOSS_PERCENT_THRESHOLD (2 << 10) /* 2 percent packet loss rate */

static boolean_t
nstat_lim_activity_check(struct if_lim_perf_stat *st)
{
	/* check that the current activity is enough to report stats */
	if (st->lim_total_txpkts < nstat_lim_min_tx_pkts ||
	    st->lim_total_rxpkts < nstat_lim_min_rx_pkts ||
	    st->lim_conn_attempts == 0) {
		return FALSE;
	}

	/*
	 * Compute percentages if there was enough activity. Use
	 * shift-left by 10 to preserve precision.
	 */
	st->lim_packet_loss_percent = ((st->lim_total_retxpkts << 10) /
	    st->lim_total_txpkts) * 100;

	st->lim_packet_ooo_percent = ((st->lim_total_oopkts << 10) /
	    st->lim_total_rxpkts) * 100;

	st->lim_conn_timeout_percent = ((st->lim_conn_timeouts << 10) /
	    st->lim_conn_attempts) * 100;

	/*
	 * Is Low Internet detected? First order metrics are bandwidth
	 * and RTT. If these metrics are below the minimum thresholds
	 * defined then the network attachment can be classified as
	 * having Low Internet capacity.
	 *
	 * High connection timeout rate also indicates Low Internet
	 * capacity.
	 */
	if (st->lim_dl_max_bandwidth > 0 &&
	    st->lim_dl_max_bandwidth <= NSTAT_LIM_DL_MAX_BANDWIDTH_THRESHOLD) {
		st->lim_dl_detected = 1;
	}

	if ((st->lim_ul_max_bandwidth > 0 &&
	    st->lim_ul_max_bandwidth <= NSTAT_LIM_UL_MAX_BANDWIDTH_THRESHOLD) ||
	    st->lim_rtt_min >= NSTAT_LIM_UL_MIN_RTT_THRESHOLD) {
		st->lim_ul_detected = 1;
	}

	if (st->lim_conn_attempts > 20 &&
	    st->lim_conn_timeout_percent >=
	    NSTAT_LIM_CONN_TIMEOUT_PERCENT_THRESHOLD) {
		st->lim_ul_detected = 1;
	}
	/*
	 * Second order metrics: If there was high packet loss even after
	 * using delay based algorithms then we classify it as Low Internet
	 * again
	 */
	if (st->lim_bk_txpkts >= nstat_lim_min_tx_pkts &&
	    st->lim_packet_loss_percent >=
	    NSTAT_LIM_PACKET_LOSS_PERCENT_THRESHOLD) {
		st->lim_ul_detected = 1;
	}
	return TRUE;
}

static u_int64_t nstat_lim_last_report_time = 0;
static void
nstat_ifnet_report_lim_stats(void)
{
	u_int64_t uptime;
	struct nstat_sysinfo_data data;
	struct nstat_sysinfo_lim_stats *st;
	struct ifnet *ifp;
	int err;

	uptime = net_uptime();

	if ((u_int32_t)(uptime - nstat_lim_last_report_time) <
	    nstat_lim_interval) {
		return;
	}

	nstat_lim_last_report_time = uptime;
	data.flags = NSTAT_SYSINFO_LIM_STATS;
	st = &data.u.lim_stats;
	data.unsent_data_cnt = 0;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (!IF_FULLY_ATTACHED(ifp)) {
			continue;
		}

		/* Limit reporting to Wifi, Ethernet and cellular */
		if (!(IFNET_IS_ETHERNET(ifp) || IFNET_IS_CELLULAR(ifp))) {
			continue;
		}

		if (!nstat_lim_activity_check(&ifp->if_lim_stat)) {
			continue;
		}

		bzero(st, sizeof(*st));
		st->ifnet_siglen = sizeof(st->ifnet_signature);
		err = ifnet_get_netsignature(ifp, AF_INET,
		    (u_int8_t *)&st->ifnet_siglen, NULL,
		    st->ifnet_signature);
		if (err != 0) {
			err = ifnet_get_netsignature(ifp, AF_INET6,
			    (u_int8_t *)&st->ifnet_siglen, NULL,
			    st->ifnet_signature);
			if (err != 0) {
				continue;
			}
		}
		ifnet_lock_shared(ifp);
		if (IFNET_IS_CELLULAR(ifp)) {
			st->ifnet_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_CELLULAR;
		} else if (IFNET_IS_WIFI(ifp)) {
			st->ifnet_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_WIFI;
		} else {
			st->ifnet_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_ETHERNET;
		}
		bcopy(&ifp->if_lim_stat, &st->lim_stat,
		    sizeof(st->lim_stat));

		/* Zero the stats in ifp */
		bzero(&ifp->if_lim_stat, sizeof(ifp->if_lim_stat));
		ifnet_lock_done(ifp);
		nstat_sysinfo_send_data(&data);
	}
	ifnet_head_done();
}

static errno_t
nstat_ifnet_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *data,
	size_t                  len)
{
	nstat_ifnet_descriptor *desc = (nstat_ifnet_descriptor *)data;
	struct nstat_ifnet_cookie *ifcookie =
	    (struct nstat_ifnet_cookie *)cookie;
	struct ifnet *ifp = ifcookie->ifp;

	if (len < sizeof(nstat_ifnet_descriptor)) {
		return EINVAL;
	}

	if (nstat_ifnet_gone(cookie)) {
		return EINVAL;
	}

	bzero(desc, sizeof(*desc));
	ifnet_lock_shared(ifp);
	strlcpy(desc->name, ifp->if_xname, sizeof(desc->name));
	desc->ifindex = ifp->if_index;
	desc->threshold = ifp->if_data_threshold;
	desc->type = ifp->if_type;
	if (ifp->if_desc.ifd_len < sizeof(desc->description)) {
		memcpy(desc->description, ifp->if_desc.ifd_desc,
		    sizeof(desc->description));
	}
	nstat_ifnet_copy_link_status(ifp, desc);
	ifnet_lock_done(ifp);
	return 0;
}

static bool
nstat_ifnet_cookie_equal(
	nstat_provider_cookie_t cookie1,
	nstat_provider_cookie_t cookie2)
{
	struct nstat_ifnet_cookie *c1 = (struct nstat_ifnet_cookie *)cookie1;
	struct nstat_ifnet_cookie *c2 = (struct nstat_ifnet_cookie *)cookie2;

	return (c1->ifp->if_index == c2->ifp->if_index) ? true : false;
}

static void
nstat_init_ifnet_provider(void)
{
	bzero(&nstat_ifnet_provider, sizeof(nstat_ifnet_provider));
	nstat_ifnet_provider.nstat_provider_id = NSTAT_PROVIDER_IFNET;
	nstat_ifnet_provider.nstat_descriptor_length = sizeof(nstat_ifnet_descriptor);
	nstat_ifnet_provider.nstat_lookup = nstat_ifnet_lookup;
	nstat_ifnet_provider.nstat_gone = nstat_ifnet_gone;
	nstat_ifnet_provider.nstat_counts = nstat_ifnet_counts;
	nstat_ifnet_provider.nstat_watcher_add = NULL;
	nstat_ifnet_provider.nstat_watcher_remove = NULL;
	nstat_ifnet_provider.nstat_copy_descriptor = nstat_ifnet_copy_descriptor;
	nstat_ifnet_provider.nstat_cookie_equal = nstat_ifnet_cookie_equal;
	nstat_ifnet_provider.nstat_release = nstat_ifnet_release;
	nstat_ifnet_provider.next = nstat_providers;
	nstat_providers = &nstat_ifnet_provider;
}

__private_extern__ void
nstat_ifnet_threshold_reached(unsigned int ifindex)
{
	nstat_control_state *state;
	nstat_src *src;
	struct ifnet *ifp;
	struct nstat_ifnet_cookie *ifcookie;

	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->ncs_mtx);
		TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
		{
			if (src->provider != &nstat_ifnet_provider) {
				continue;
			}
			ifcookie = (struct nstat_ifnet_cookie *)src->cookie;
			ifp = ifcookie->ifp;
			if (ifp->if_index != ifindex) {
				continue;
			}
			nstat_control_send_counts(state, src, 0, 0, NULL);
		}
		lck_mtx_unlock(&state->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

#pragma mark -- Sysinfo --
static void
nstat_set_keyval_scalar(nstat_sysinfo_keyval *kv, int key, u_int32_t val)
{
	kv->nstat_sysinfo_key = key;
	kv->nstat_sysinfo_flags = NSTAT_SYSINFO_FLAG_SCALAR;
	kv->u.nstat_sysinfo_scalar = val;
	kv->nstat_sysinfo_valsize = sizeof(kv->u.nstat_sysinfo_scalar);
}

static void
nstat_set_keyval_u64_scalar(nstat_sysinfo_keyval *kv, int key, u_int64_t val)
{
	kv->nstat_sysinfo_key = key;
	kv->nstat_sysinfo_flags = NSTAT_SYSINFO_FLAG_SCALAR;
	kv->u.nstat_sysinfo_scalar = val;
	kv->nstat_sysinfo_valsize = sizeof(kv->u.nstat_sysinfo_scalar);
}

static void
nstat_set_keyval_string(nstat_sysinfo_keyval *kv, int key, u_int8_t *buf,
    u_int32_t len)
{
	kv->nstat_sysinfo_key = key;
	kv->nstat_sysinfo_flags = NSTAT_SYSINFO_FLAG_STRING;
	kv->nstat_sysinfo_valsize = min(len,
	    NSTAT_SYSINFO_KEYVAL_STRING_MAXSIZE);
	bcopy(buf, kv->u.nstat_sysinfo_string, kv->nstat_sysinfo_valsize);
}

static void
nstat_sysinfo_send_data_internal(
	nstat_control_state *control,
	nstat_sysinfo_data *data)
{
	nstat_msg_sysinfo_counts *syscnt = NULL;
	size_t allocsize = 0, countsize = 0, nkeyvals = 0, finalsize = 0;
	nstat_sysinfo_keyval *kv;
	errno_t result = 0;
	size_t i = 0;

	allocsize = offsetof(nstat_msg_sysinfo_counts, counts);
	countsize = offsetof(nstat_sysinfo_counts, nstat_sysinfo_keyvals);
	finalsize = allocsize;

	/* get number of key-vals for each kind of stat */
	switch (data->flags) {
	case NSTAT_SYSINFO_MBUF_STATS:
		nkeyvals = sizeof(struct nstat_sysinfo_mbuf_stats) /
		    sizeof(u_int32_t);
		break;
	case NSTAT_SYSINFO_TCP_STATS:
		nkeyvals = NSTAT_SYSINFO_TCP_STATS_COUNT;
		break;
	case NSTAT_SYSINFO_IFNET_ECN_STATS:
		nkeyvals = (sizeof(struct if_tcp_ecn_stat) /
		    sizeof(u_int64_t));

		/* Two more keys for ifnet type and proto */
		nkeyvals += 2;

		/* One key for unsent data. */
		nkeyvals++;
		break;
	case NSTAT_SYSINFO_LIM_STATS:
		nkeyvals = NSTAT_LIM_STAT_KEYVAL_COUNT;
		break;
	case NSTAT_SYSINFO_NET_API_STATS:
		nkeyvals = NSTAT_NET_API_STAT_KEYVAL_COUNT;
		break;
	default:
		return;
	}
	countsize += sizeof(nstat_sysinfo_keyval) * nkeyvals;
	allocsize += countsize;

	syscnt = (nstat_msg_sysinfo_counts *) kalloc_data(allocsize,
	    Z_WAITOK | Z_ZERO);
	if (syscnt == NULL) {
		return;
	}

	kv = (nstat_sysinfo_keyval *) &syscnt->counts.nstat_sysinfo_keyvals;
	switch (data->flags) {
	case NSTAT_SYSINFO_MBUF_STATS:
	{
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_MBUF_256B_TOTAL,
		    data->u.mb_stats.total_256b);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_MBUF_2KB_TOTAL,
		    data->u.mb_stats.total_2kb);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_MBUF_4KB_TOTAL,
		    data->u.mb_stats.total_4kb);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MBUF_16KB_TOTAL,
		    data->u.mb_stats.total_16kb);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_SOCK_MBCNT,
		    data->u.mb_stats.sbmb_total);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_SOCK_ATMBLIMIT,
		    data->u.mb_stats.sb_atmbuflimit);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MBUF_DRAIN_CNT,
		    data->u.mb_stats.draincnt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MBUF_MEM_RELEASED,
		    data->u.mb_stats.memreleased);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_SOCK_MBFLOOR,
		    data->u.mb_stats.sbmb_floor);
		VERIFY(i == nkeyvals);
		break;
	}
	case NSTAT_SYSINFO_TCP_STATS:
	{
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_IPV4_AVGRTT,
		    data->u.tcp_stats.ipv4_avgrtt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_IPV6_AVGRTT,
		    data->u.tcp_stats.ipv6_avgrtt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_SEND_PLR,
		    data->u.tcp_stats.send_plr);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_RECV_PLR,
		    data->u.tcp_stats.recv_plr);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_SEND_TLRTO,
		    data->u.tcp_stats.send_tlrto_rate);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_KEY_SEND_REORDERRATE,
		    data->u.tcp_stats.send_reorder_rate);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_CONNECTION_ATTEMPTS,
		    data->u.tcp_stats.connection_attempts);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_CONNECTION_ACCEPTS,
		    data->u.tcp_stats.connection_accepts);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CLIENT_ENABLED,
		    data->u.tcp_stats.ecn_client_enabled);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_SERVER_ENABLED,
		    data->u.tcp_stats.ecn_server_enabled);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CLIENT_SETUP,
		    data->u.tcp_stats.ecn_client_setup);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_SERVER_SETUP,
		    data->u.tcp_stats.ecn_server_setup);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CLIENT_SUCCESS,
		    data->u.tcp_stats.ecn_client_success);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_SERVER_SUCCESS,
		    data->u.tcp_stats.ecn_server_success);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_NOT_SUPPORTED,
		    data->u.tcp_stats.ecn_not_supported);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_LOST_SYN,
		    data->u.tcp_stats.ecn_lost_syn);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_LOST_SYNACK,
		    data->u.tcp_stats.ecn_lost_synack);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_RECV_CE,
		    data->u.tcp_stats.ecn_recv_ce);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_RECV_ECE,
		    data->u.tcp_stats.ecn_recv_ece);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_SENT_ECE,
		    data->u.tcp_stats.ecn_sent_ece);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CONN_RECV_CE,
		    data->u.tcp_stats.ecn_conn_recv_ce);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CONN_RECV_ECE,
		    data->u.tcp_stats.ecn_conn_recv_ece);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CONN_PLNOCE,
		    data->u.tcp_stats.ecn_conn_plnoce);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CONN_PL_CE,
		    data->u.tcp_stats.ecn_conn_pl_ce);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_CONN_NOPL_CE,
		    data->u.tcp_stats.ecn_conn_nopl_ce);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_FALLBACK_SYNLOSS,
		    data->u.tcp_stats.ecn_fallback_synloss);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_FALLBACK_REORDER,
		    data->u.tcp_stats.ecn_fallback_reorder);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_FALLBACK_CE,
		    data->u.tcp_stats.ecn_fallback_ce);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_SYN_DATA_RCV,
		    data->u.tcp_stats.tfo_syn_data_rcv);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_COOKIE_REQ_RCV,
		    data->u.tcp_stats.tfo_cookie_req_rcv);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_COOKIE_SENT,
		    data->u.tcp_stats.tfo_cookie_sent);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_COOKIE_INVALID,
		    data->u.tcp_stats.tfo_cookie_invalid);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_COOKIE_REQ,
		    data->u.tcp_stats.tfo_cookie_req);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_COOKIE_RCV,
		    data->u.tcp_stats.tfo_cookie_rcv);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_SYN_DATA_SENT,
		    data->u.tcp_stats.tfo_syn_data_sent);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_SYN_DATA_ACKED,
		    data->u.tcp_stats.tfo_syn_data_acked);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_SYN_LOSS,
		    data->u.tcp_stats.tfo_syn_loss);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_BLACKHOLE,
		    data->u.tcp_stats.tfo_blackhole);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_COOKIE_WRONG,
		    data->u.tcp_stats.tfo_cookie_wrong);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_NO_COOKIE_RCV,
		    data->u.tcp_stats.tfo_no_cookie_rcv);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_HEURISTICS_DISABLE,
		    data->u.tcp_stats.tfo_heuristics_disable);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_TFO_SEND_BLACKHOLE,
		    data->u.tcp_stats.tfo_sndblackhole);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_ATTEMPT,
		    data->u.tcp_stats.mptcp_handover_attempt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_INTERACTIVE_ATTEMPT,
		    data->u.tcp_stats.mptcp_interactive_attempt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_AGGREGATE_ATTEMPT,
		    data->u.tcp_stats.mptcp_aggregate_attempt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_HANDOVER_ATTEMPT,
		    data->u.tcp_stats.mptcp_fp_handover_attempt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_INTERACTIVE_ATTEMPT,
		    data->u.tcp_stats.mptcp_fp_interactive_attempt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_AGGREGATE_ATTEMPT,
		    data->u.tcp_stats.mptcp_fp_aggregate_attempt);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HEURISTIC_FALLBACK,
		    data->u.tcp_stats.mptcp_heuristic_fallback);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_HEURISTIC_FALLBACK,
		    data->u.tcp_stats.mptcp_fp_heuristic_fallback);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_SUCCESS_WIFI,
		    data->u.tcp_stats.mptcp_handover_success_wifi);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_SUCCESS_CELL,
		    data->u.tcp_stats.mptcp_handover_success_cell);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_INTERACTIVE_SUCCESS,
		    data->u.tcp_stats.mptcp_interactive_success);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_AGGREGATE_SUCCESS,
		    data->u.tcp_stats.mptcp_aggregate_success);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_HANDOVER_SUCCESS_WIFI,
		    data->u.tcp_stats.mptcp_fp_handover_success_wifi);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_HANDOVER_SUCCESS_CELL,
		    data->u.tcp_stats.mptcp_fp_handover_success_cell);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_INTERACTIVE_SUCCESS,
		    data->u.tcp_stats.mptcp_fp_interactive_success);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_FP_AGGREGATE_SUCCESS,
		    data->u.tcp_stats.mptcp_fp_aggregate_success);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_CELL_FROM_WIFI,
		    data->u.tcp_stats.mptcp_handover_cell_from_wifi);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_WIFI_FROM_CELL,
		    data->u.tcp_stats.mptcp_handover_wifi_from_cell);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_INTERACTIVE_CELL_FROM_WIFI,
		    data->u.tcp_stats.mptcp_interactive_cell_from_wifi);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_CELL_BYTES,
		    data->u.tcp_stats.mptcp_handover_cell_bytes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_INTERACTIVE_CELL_BYTES,
		    data->u.tcp_stats.mptcp_interactive_cell_bytes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_AGGREGATE_CELL_BYTES,
		    data->u.tcp_stats.mptcp_aggregate_cell_bytes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_HANDOVER_ALL_BYTES,
		    data->u.tcp_stats.mptcp_handover_all_bytes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_INTERACTIVE_ALL_BYTES,
		    data->u.tcp_stats.mptcp_interactive_all_bytes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_AGGREGATE_ALL_BYTES,
		    data->u.tcp_stats.mptcp_aggregate_all_bytes);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_BACK_TO_WIFI,
		    data->u.tcp_stats.mptcp_back_to_wifi);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_WIFI_PROXY,
		    data->u.tcp_stats.mptcp_wifi_proxy);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_CELL_PROXY,
		    data->u.tcp_stats.mptcp_cell_proxy);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_MPTCP_TRIGGERED_CELL,
		    data->u.tcp_stats.mptcp_triggered_cell);
		VERIFY(i == nkeyvals);
		break;
	}
	case NSTAT_SYSINFO_IFNET_ECN_STATS:
	{
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_TYPE,
		    data->u.ifnet_ecn_stats.ifnet_type);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_PROTO,
		    data->u.ifnet_ecn_stats.ifnet_proto);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CLIENT_SETUP,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_client_setup);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_SERVER_SETUP,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_server_setup);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CLIENT_SUCCESS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_client_success);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_SERVER_SUCCESS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_server_success);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_PEER_NOSUPPORT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_peer_nosupport);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_SYN_LOST,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_syn_lost);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_SYNACK_LOST,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_synack_lost);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_RECV_CE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_recv_ce);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_RECV_ECE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_recv_ece);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CONN_RECV_CE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_recv_ce);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CONN_RECV_ECE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_recv_ece);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CONN_PLNOCE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_plnoce);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CONN_PLCE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_plce);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_CONN_NOPLCE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_noplce);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_SYNLOSS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_synloss);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_REORDER,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_reorder);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_CE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_ce);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_RTT_AVG,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rtt_avg);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_RTT_VAR,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rtt_var);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_OOPERCENT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.oo_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_SACK_EPISODE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.sack_episodes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_REORDER_PERCENT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.reorder_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_RXMIT_PERCENT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rxmit_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_RXMIT_DROP,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rxmit_drop);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_RTT_AVG,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rtt_avg);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_RTT_VAR,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rtt_var);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_OOPERCENT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.oo_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_SACK_EPISODE,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.sack_episodes);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_REORDER_PERCENT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.reorder_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_RXMIT_PERCENT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rxmit_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_RXMIT_DROP,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rxmit_drop);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_TXPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_txpkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_RXMTPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_rxmitpkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_RXPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_rxpkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_OOPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_oopkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_ON_DROP_RST,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rst_drop);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_TXPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_txpkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_RXMTPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_rxmitpkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_RXPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_rxpkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_OOPKTS,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_oopkts);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_OFF_DROP_RST,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rst_drop);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_TOTAL_CONN,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_total_conn);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_IFNET_UNSENT_DATA,
		    data->unsent_data_cnt);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_DROPRST,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_droprst);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_DROPRXMT,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_droprxmt);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_SYNRST,
		    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_synrst);
		break;
	}
	case NSTAT_SYSINFO_LIM_STATS:
	{
		nstat_set_keyval_string(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_SIGNATURE,
		    data->u.lim_stats.ifnet_signature,
		    data->u.lim_stats.ifnet_siglen);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_DL_MAX_BANDWIDTH,
		    data->u.lim_stats.lim_stat.lim_dl_max_bandwidth);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_UL_MAX_BANDWIDTH,
		    data->u.lim_stats.lim_stat.lim_ul_max_bandwidth);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_PACKET_LOSS_PERCENT,
		    data->u.lim_stats.lim_stat.lim_packet_loss_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_PACKET_OOO_PERCENT,
		    data->u.lim_stats.lim_stat.lim_packet_ooo_percent);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_RTT_VARIANCE,
		    data->u.lim_stats.lim_stat.lim_rtt_variance);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_RTT_MIN,
		    data->u.lim_stats.lim_stat.lim_rtt_min);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_RTT_AVG,
		    data->u.lim_stats.lim_stat.lim_rtt_average);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_CONN_TIMEOUT_PERCENT,
		    data->u.lim_stats.lim_stat.lim_conn_timeout_percent);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_DL_DETECTED,
		    data->u.lim_stats.lim_stat.lim_dl_detected);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_UL_DETECTED,
		    data->u.lim_stats.lim_stat.lim_ul_detected);
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_TYPE,
		    data->u.lim_stats.ifnet_type);
		break;
	}
	case NSTAT_SYSINFO_NET_API_STATS:
	{
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IF_FLTR_ATTACH,
		    data->u.net_api_stats.net_api_stats.nas_iflt_attach_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IF_FLTR_ATTACH_OS,
		    data->u.net_api_stats.net_api_stats.nas_iflt_attach_os_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IP_FLTR_ADD,
		    data->u.net_api_stats.net_api_stats.nas_ipf_add_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IP_FLTR_ADD_OS,
		    data->u.net_api_stats.net_api_stats.nas_ipf_add_os_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_FLTR_ATTACH,
		    data->u.net_api_stats.net_api_stats.nas_sfltr_register_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_FLTR_ATTACH_OS,
		    data->u.net_api_stats.net_api_stats.nas_sfltr_register_os_total);


		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_ALLOC_TOTAL,
		    data->u.net_api_stats.net_api_stats.nas_socket_alloc_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_ALLOC_KERNEL,
		    data->u.net_api_stats.net_api_stats.nas_socket_in_kernel_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_ALLOC_KERNEL_OS,
		    data->u.net_api_stats.net_api_stats.nas_socket_in_kernel_os_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_NECP_CLIENTUUID,
		    data->u.net_api_stats.net_api_stats.nas_socket_necp_clientuuid_total);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_LOCAL,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_local_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_ROUTE,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_route_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_INET,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_inet_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_INET6,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_inet6_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_SYSTEM,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_system_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_MULTIPATH,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_multipath_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_KEY,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_key_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_NDRV,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_ndrv_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_DOMAIN_OTHER,
		    data->u.net_api_stats.net_api_stats.nas_socket_domain_other_total);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_STREAM,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet_stream_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_DGRAM,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet_dgram_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_DGRAM_CONNECTED,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet_dgram_connected);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_DGRAM_DNS,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet_dgram_dns);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_DGRAM_NO_DATA,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet_dgram_no_data);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET6_STREAM,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet6_stream_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET6_DGRAM,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet6_dgram_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET6_DGRAM_CONNECTED,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet6_dgram_connected);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET6_DGRAM_DNS,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet6_dgram_dns);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET6_DGRAM_NO_DATA,
		    data->u.net_api_stats.net_api_stats.nas_socket_inet6_dgram_no_data);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_MCAST_JOIN,
		    data->u.net_api_stats.net_api_stats.nas_socket_mcast_join_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_SOCK_INET_MCAST_JOIN_OS,
		    data->u.net_api_stats.net_api_stats.nas_socket_mcast_join_os_total);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_NEXUS_FLOW_INET_STREAM,
		    data->u.net_api_stats.net_api_stats.nas_nx_flow_inet_stream_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_NEXUS_FLOW_INET_DATAGRAM,
		    data->u.net_api_stats.net_api_stats.nas_nx_flow_inet_dgram_total);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_NEXUS_FLOW_INET6_STREAM,
		    data->u.net_api_stats.net_api_stats.nas_nx_flow_inet6_stream_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_NEXUS_FLOW_INET6_DATAGRAM,
		    data->u.net_api_stats.net_api_stats.nas_nx_flow_inet6_dgram_total);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IFNET_ALLOC,
		    data->u.net_api_stats.net_api_stats.nas_ifnet_alloc_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IFNET_ALLOC_OS,
		    data->u.net_api_stats.net_api_stats.nas_ifnet_alloc_os_total);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_PF_ADDRULE,
		    data->u.net_api_stats.net_api_stats.nas_pf_addrule_total);
		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_PF_ADDRULE_OS,
		    data->u.net_api_stats.net_api_stats.nas_pf_addrule_os);

		nstat_set_keyval_u64_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_VMNET_START,
		    data->u.net_api_stats.net_api_stats.nas_vmnet_total);

#if SKYWALK
		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_IF_NETAGENT_ENABLED,
		    if_is_fsw_transport_netagent_enabled());
#endif /* SKYWALK */

		nstat_set_keyval_scalar(&kv[i++],
		    NSTAT_SYSINFO_API_REPORT_INTERVAL,
		    data->u.net_api_stats.report_interval);

		break;
	}
	}
	if (syscnt != NULL) {
		VERIFY(i > 0 && i <= nkeyvals);
		countsize = offsetof(nstat_sysinfo_counts,
		    nstat_sysinfo_keyvals) +
		    sizeof(nstat_sysinfo_keyval) * i;
		finalsize += countsize;
		syscnt->hdr.type = NSTAT_MSG_TYPE_SYSINFO_COUNTS;
		assert(finalsize <= MAX_NSTAT_MSG_HDR_LENGTH);
		syscnt->hdr.length = (u_int16_t)finalsize;
		syscnt->counts.nstat_sysinfo_len = (u_int32_t)countsize;

		result = ctl_enqueuedata(control->ncs_kctl,
		    control->ncs_unit, syscnt, finalsize, CTL_DATA_EOR);
		if (result != 0) {
			nstat_stats.nstat_sysinfofailures += 1;
		}
		kfree_data(syscnt, allocsize);
	}
	return;
}

__private_extern__ void
nstat_sysinfo_send_data(
	nstat_sysinfo_data *data)
{
	nstat_control_state *control;

	lck_mtx_lock(&nstat_mtx);
	for (control = nstat_controls; control; control = control->ncs_next) {
		lck_mtx_lock(&control->ncs_mtx);
		if ((control->ncs_flags & NSTAT_FLAG_SYSINFO_SUBSCRIBED) != 0) {
			nstat_sysinfo_send_data_internal(control, data);
		}
		lck_mtx_unlock(&control->ncs_mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

static void
nstat_sysinfo_generate_report(void)
{
	mbuf_report_peak_usage();
	tcp_report_stats();
	nstat_ifnet_report_ecn_stats();
	nstat_ifnet_report_lim_stats();
	nstat_net_api_report_stats();
}

#pragma mark -- net_api --

static struct net_api_stats net_api_stats_before;
static u_int64_t net_api_stats_last_report_time;

static void
nstat_net_api_report_stats(void)
{
	struct nstat_sysinfo_data data;
	struct nstat_sysinfo_net_api_stats *st = &data.u.net_api_stats;
	u_int64_t uptime;

	uptime = net_uptime();

	if ((u_int32_t)(uptime - net_api_stats_last_report_time) <
	    net_api_stats_report_interval) {
		return;
	}

	st->report_interval = (u_int32_t)(uptime - net_api_stats_last_report_time);
	net_api_stats_last_report_time = uptime;

	data.flags = NSTAT_SYSINFO_NET_API_STATS;
	data.unsent_data_cnt = 0;

	/*
	 * Some of the fields in the report are the current value and
	 * other fields are the delta from the last report:
	 * - Report difference for the per flow counters as they increase
	 *   with time
	 * - Report current value for other counters as they tend not to change
	 *   much with time
	 */
#define STATCOPY(f) \
	(st->net_api_stats.f = net_api_stats.f)
#define STATDIFF(f) \
	(st->net_api_stats.f = net_api_stats.f - net_api_stats_before.f)

	STATCOPY(nas_iflt_attach_count);
	STATCOPY(nas_iflt_attach_total);
	STATCOPY(nas_iflt_attach_os_total);

	STATCOPY(nas_ipf_add_count);
	STATCOPY(nas_ipf_add_total);
	STATCOPY(nas_ipf_add_os_total);

	STATCOPY(nas_sfltr_register_count);
	STATCOPY(nas_sfltr_register_total);
	STATCOPY(nas_sfltr_register_os_total);

	STATDIFF(nas_socket_alloc_total);
	STATDIFF(nas_socket_in_kernel_total);
	STATDIFF(nas_socket_in_kernel_os_total);
	STATDIFF(nas_socket_necp_clientuuid_total);

	STATDIFF(nas_socket_domain_local_total);
	STATDIFF(nas_socket_domain_route_total);
	STATDIFF(nas_socket_domain_inet_total);
	STATDIFF(nas_socket_domain_inet6_total);
	STATDIFF(nas_socket_domain_system_total);
	STATDIFF(nas_socket_domain_multipath_total);
	STATDIFF(nas_socket_domain_key_total);
	STATDIFF(nas_socket_domain_ndrv_total);
	STATDIFF(nas_socket_domain_other_total);

	STATDIFF(nas_socket_inet_stream_total);
	STATDIFF(nas_socket_inet_dgram_total);
	STATDIFF(nas_socket_inet_dgram_connected);
	STATDIFF(nas_socket_inet_dgram_dns);
	STATDIFF(nas_socket_inet_dgram_no_data);

	STATDIFF(nas_socket_inet6_stream_total);
	STATDIFF(nas_socket_inet6_dgram_total);
	STATDIFF(nas_socket_inet6_dgram_connected);
	STATDIFF(nas_socket_inet6_dgram_dns);
	STATDIFF(nas_socket_inet6_dgram_no_data);

	STATDIFF(nas_socket_mcast_join_total);
	STATDIFF(nas_socket_mcast_join_os_total);

	STATDIFF(nas_sock_inet6_stream_exthdr_in);
	STATDIFF(nas_sock_inet6_stream_exthdr_out);
	STATDIFF(nas_sock_inet6_dgram_exthdr_in);
	STATDIFF(nas_sock_inet6_dgram_exthdr_out);

	STATDIFF(nas_nx_flow_inet_stream_total);
	STATDIFF(nas_nx_flow_inet_dgram_total);

	STATDIFF(nas_nx_flow_inet6_stream_total);
	STATDIFF(nas_nx_flow_inet6_dgram_total);

	STATCOPY(nas_ifnet_alloc_count);
	STATCOPY(nas_ifnet_alloc_total);
	STATCOPY(nas_ifnet_alloc_os_count);
	STATCOPY(nas_ifnet_alloc_os_total);

	STATCOPY(nas_pf_addrule_total);
	STATCOPY(nas_pf_addrule_os);

	STATCOPY(nas_vmnet_total);

#undef STATCOPY
#undef STATDIFF

	nstat_sysinfo_send_data(&data);

	/*
	 * Save a copy of the current fields so we can diff them the next time
	 */
	memcpy(&net_api_stats_before, &net_api_stats,
	    sizeof(struct net_api_stats));
	_CASSERT(sizeof(net_api_stats_before) == sizeof(net_api_stats));
}


#pragma mark -- Kernel Control Socket --

static kern_ctl_ref     nstat_ctlref = NULL;

static errno_t  nstat_control_connect(kern_ctl_ref kctl, struct sockaddr_ctl *sac, void **uinfo);
static errno_t  nstat_control_disconnect(kern_ctl_ref kctl, u_int32_t unit, void *uinfo);
static errno_t  nstat_control_send(kern_ctl_ref kctl, u_int32_t unit, void *uinfo, mbuf_t m, int flags);

static errno_t
nstat_enqueue_success(
	uint64_t context,
	nstat_control_state *state,
	u_int16_t flags)
{
	nstat_msg_hdr success;
	errno_t result;

	bzero(&success, sizeof(success));
	success.context = context;
	success.type = NSTAT_MSG_TYPE_SUCCESS;
	success.length = sizeof(success);
	success.flags = flags;
	result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, &success,
	    sizeof(success), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		if (nstat_debug != 0) {
			printf("%s: could not enqueue success message %d\n",
			    __func__, result);
		}
		nstat_stats.nstat_successmsgfailures += 1;
	}
	return result;
}

static errno_t
nstat_control_send_event(
	nstat_control_state     *state,
	nstat_src                       *src,
	u_int64_t               event)
{
	errno_t result = 0;
	int failed = 0;

	if (nstat_control_reporting_allowed(state, src, 0)) {
		if ((state->ncs_flags & NSTAT_FLAG_SUPPORTS_UPDATES) != 0) {
			result = nstat_control_send_update(state, src, 0, event, 0, NULL);
			if (result != 0) {
				failed = 1;
				if (nstat_debug != 0) {
					printf("%s - nstat_control_send_event() %d\n", __func__, result);
				}
			}
		} else {
			if (nstat_debug != 0) {
				printf("%s - nstat_control_send_event() used when updates not supported\n", __func__);
			}
		}
	}
	return result;
}

static errno_t
nstat_control_send_goodbye(
	nstat_control_state     *state,
	nstat_src               *src)
{
	errno_t result = 0;
	int failed = 0;
	u_int16_t hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_FILTER;

	if (nstat_control_reporting_allowed(state, src, (src->ns_reported)? NSTAT_FILTER_SUPPRESS_BORING_CLOSE: 0)) {
		hdr_flags = 0;
		if ((state->ncs_flags & NSTAT_FLAG_SUPPORTS_UPDATES) != 0) {
			result = nstat_control_send_update(state, src, 0, 0, NSTAT_MSG_HDR_FLAG_CLOSING, NULL);
			if (result != 0) {
				failed = 1;
				hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_DROP;
				if (nstat_debug != 0) {
					printf("%s - nstat_control_send_update() %d\n", __func__, result);
				}
			}
		} else {
			// send one last counts notification
			result = nstat_control_send_counts(state, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING, NULL);
			if (result != 0) {
				failed = 1;
				hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_DROP;
				if (nstat_debug != 0) {
					printf("%s - nstat_control_send_counts() %d\n", __func__, result);
				}
			}

			// send a last description
			result = nstat_control_send_description(state, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING);
			if (result != 0) {
				failed = 1;
				hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_DROP;
				if (nstat_debug != 0) {
					printf("%s - nstat_control_send_description() %d\n", __func__, result);
				}
			}
		}
	}

	// send the source removed notification
	result = nstat_control_send_removed(state, src, hdr_flags);
	if (result != 0 && nstat_debug) {
		failed = 1;
		if (nstat_debug != 0) {
			printf("%s - nstat_control_send_removed() %d\n", __func__, result);
		}
	}

	if (failed != 0) {
		nstat_stats.nstat_control_send_goodbye_failures++;
	}


	return result;
}

static errno_t
nstat_flush_accumulated_msgs(
	nstat_control_state     *state)
{
	errno_t result = 0;
	if (state->ncs_accumulated != NULL && mbuf_len(state->ncs_accumulated) > 0) {
		mbuf_pkthdr_setlen(state->ncs_accumulated, mbuf_len(state->ncs_accumulated));
		result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, state->ncs_accumulated, CTL_DATA_EOR);
		if (result != 0) {
			nstat_stats.nstat_flush_accumulated_msgs_failures++;
			if (nstat_debug != 0) {
				printf("%s - ctl_enqueuembuf failed: %d\n", __func__, result);
			}
			mbuf_freem(state->ncs_accumulated);
		}
		state->ncs_accumulated = NULL;
	}
	return result;
}

static errno_t
nstat_accumulate_msg(
	nstat_control_state     *state,
	nstat_msg_hdr           *hdr,
	size_t                  length)
{
	assert(length <= MAX_NSTAT_MSG_HDR_LENGTH);

	if (state->ncs_accumulated && mbuf_trailingspace(state->ncs_accumulated) < length) {
		// Will send the current mbuf
		nstat_flush_accumulated_msgs(state);
	}

	errno_t result = 0;

	if (state->ncs_accumulated == NULL) {
		unsigned int one = 1;
		if (mbuf_allocpacket(MBUF_DONTWAIT, NSTAT_MAX_MSG_SIZE, &one, &state->ncs_accumulated) != 0) {
			if (nstat_debug != 0) {
				printf("%s - mbuf_allocpacket failed\n", __func__);
			}
			result = ENOMEM;
		} else {
			mbuf_setlen(state->ncs_accumulated, 0);
		}
	}

	if (result == 0) {
		hdr->length = (u_int16_t)length;
		result = mbuf_copyback(state->ncs_accumulated, mbuf_len(state->ncs_accumulated),
		    length, hdr, MBUF_DONTWAIT);
	}

	if (result != 0) {
		nstat_flush_accumulated_msgs(state);
		if (nstat_debug != 0) {
			printf("%s - resorting to ctl_enqueuedata\n", __func__);
		}
		result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, hdr, length, CTL_DATA_EOR);
	}

	if (result != 0) {
		nstat_stats.nstat_accumulate_msg_failures++;
	}

	return result;
}

static void
nstat_idle_check(
	__unused thread_call_param_t p0,
	__unused thread_call_param_t p1)
{
	nstat_control_state *control;
	nstat_src  *src, *tmpsrc;
	tailq_head_nstat_src dead_list;
	TAILQ_INIT(&dead_list);

	lck_mtx_lock(&nstat_mtx);

	nstat_idle_time = 0;

	for (control = nstat_controls; control; control = control->ncs_next) {
		lck_mtx_lock(&control->ncs_mtx);
		if (!(control->ncs_flags & NSTAT_FLAG_REQCOUNTS)) {
			TAILQ_FOREACH_SAFE(src, &control->ncs_src_queue, ns_control_link, tmpsrc)
			{
				if (src->provider->nstat_gone(src->cookie)) {
					errno_t result;

					// Pull it off the list
					TAILQ_REMOVE(&control->ncs_src_queue, src, ns_control_link);

					result = nstat_control_send_goodbye(control, src);

					// Put this on the list to release later
					TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
				}
			}
		}
		control->ncs_flags &= ~NSTAT_FLAG_REQCOUNTS;
		lck_mtx_unlock(&control->ncs_mtx);
	}

	if (nstat_controls) {
		clock_interval_to_deadline(60, NSEC_PER_SEC, &nstat_idle_time);
		thread_call_func_delayed((thread_call_func_t)nstat_idle_check, NULL, nstat_idle_time);
	}

	lck_mtx_unlock(&nstat_mtx);

	/* Generate any system level reports, if needed */
	nstat_sysinfo_generate_report();

	// Release the sources now that we aren't holding lots of locks
	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		nstat_control_cleanup_source(NULL, src, FALSE);
	}

	nstat_prune_procdetails();
}

static void
nstat_control_register(void)
{
	// Register the control
	struct kern_ctl_reg     nstat_control;
	bzero(&nstat_control, sizeof(nstat_control));
	strlcpy(nstat_control.ctl_name, NET_STAT_CONTROL_NAME, sizeof(nstat_control.ctl_name));
	nstat_control.ctl_flags = CTL_FLAG_REG_EXTENDED | CTL_FLAG_REG_CRIT;
	nstat_control.ctl_sendsize = nstat_sendspace;
	nstat_control.ctl_recvsize = nstat_recvspace;
	nstat_control.ctl_connect = nstat_control_connect;
	nstat_control.ctl_disconnect = nstat_control_disconnect;
	nstat_control.ctl_send = nstat_control_send;

	ctl_register(&nstat_control, &nstat_ctlref);
}

static void
nstat_control_cleanup_source(
	nstat_control_state     *state,
	struct nstat_src        *src,
	boolean_t               locked)
{
	errno_t result;

	if (state) {
		result = nstat_control_send_removed(state, src, 0);
		if (result != 0) {
			nstat_stats.nstat_control_cleanup_source_failures++;
			if (nstat_debug != 0) {
				printf("%s - nstat_control_send_removed() %d\n",
				    __func__, result);
			}
		}
	}
	// Cleanup the source if we found it.
	src->provider->nstat_release(src->cookie, locked);
	kfree_type(struct nstat_src, src);
}


static bool
nstat_control_reporting_allowed(
	nstat_control_state *state,
	nstat_src *src,
	u_int64_t suppression_flags)
{
	if (src->provider->nstat_reporting_allowed == NULL) {
		return TRUE;
	}

	return src->provider->nstat_reporting_allowed(src->cookie,
	           &state->ncs_provider_filters[src->provider->nstat_provider_id], suppression_flags);
}


static errno_t
nstat_control_connect(
	kern_ctl_ref        kctl,
	struct sockaddr_ctl *sac,
	void                **uinfo)
{
	nstat_control_state *state = kalloc_type(nstat_control_state,
	    Z_WAITOK | Z_ZERO);
	if (state == NULL) {
		return ENOMEM;
	}

	lck_mtx_init(&state->ncs_mtx, &nstat_lck_grp, NULL);
	state->ncs_kctl = kctl;
	state->ncs_unit = sac->sc_unit;
	state->ncs_flags = NSTAT_FLAG_REQCOUNTS;
	state->ncs_procdetails = nstat_retain_curprocdetails();
	*uinfo = state;

	lck_mtx_lock(&nstat_mtx);
	state->ncs_next = nstat_controls;
	nstat_controls = state;

	if (nstat_idle_time == 0) {
		clock_interval_to_deadline(60, NSEC_PER_SEC, &nstat_idle_time);
		thread_call_func_delayed((thread_call_func_t)nstat_idle_check, NULL, nstat_idle_time);
	}

	merge_current_event_filters();
	lck_mtx_unlock(&nstat_mtx);

	return 0;
}

static errno_t
nstat_control_disconnect(
	__unused kern_ctl_ref   kctl,
	__unused u_int32_t      unit,
	void                    *uinfo)
{
	u_int32_t   watching;
	nstat_control_state *state = (nstat_control_state*)uinfo;
	tailq_head_nstat_src cleanup_list;
	nstat_src *src;

	TAILQ_INIT(&cleanup_list);

	// pull it out of the global list of states
	lck_mtx_lock(&nstat_mtx);
	nstat_control_state     **statepp;
	for (statepp = &nstat_controls; *statepp; statepp = &(*statepp)->ncs_next) {
		if (*statepp == state) {
			*statepp = state->ncs_next;
			break;
		}
	}
	merge_current_event_filters();
	lck_mtx_unlock(&nstat_mtx);

	lck_mtx_lock(&state->ncs_mtx);
	// Stop watching for sources
	nstat_provider  *provider;
	watching = state->ncs_watching;
	state->ncs_watching = 0;
	for (provider = nstat_providers; provider && watching; provider = provider->next) {
		if ((watching & (1 << provider->nstat_provider_id)) != 0) {
			watching &= ~(1 << provider->nstat_provider_id);
			provider->nstat_watcher_remove(state);
		}
	}

	// set cleanup flags
	state->ncs_flags |= NSTAT_FLAG_CLEANUP;

	if (state->ncs_accumulated) {
		mbuf_freem(state->ncs_accumulated);
		state->ncs_accumulated = NULL;
	}

	// Copy out the list of sources
	TAILQ_CONCAT(&cleanup_list, &state->ncs_src_queue, ns_control_link);
	lck_mtx_unlock(&state->ncs_mtx);

	while ((src = TAILQ_FIRST(&cleanup_list))) {
		TAILQ_REMOVE(&cleanup_list, src, ns_control_link);
		nstat_control_cleanup_source(NULL, src, FALSE);
	}

	lck_mtx_destroy(&state->ncs_mtx, &nstat_lck_grp);
	nstat_release_procdetails(state->ncs_procdetails);
	kfree_type(struct nstat_control_state, state);

	return 0;
}

static nstat_src_ref_t
nstat_control_next_src_ref(
	nstat_control_state     *state)
{
	return ++state->ncs_next_srcref;
}

static errno_t
nstat_control_send_counts(
	nstat_control_state *state,
	nstat_src           *src,
	unsigned long long  context,
	u_int16_t           hdr_flags,
	int                 *gone)
{
	nstat_msg_src_counts counts;
	errno_t result = 0;

	/* Some providers may not have any counts to send */
	if (src->provider->nstat_counts == NULL) {
		return 0;
	}

	bzero(&counts, sizeof(counts));
	counts.hdr.type = NSTAT_MSG_TYPE_SRC_COUNTS;
	counts.hdr.length = sizeof(counts);
	counts.hdr.flags = hdr_flags;
	counts.hdr.context = context;
	counts.srcref = src->srcref;
	counts.event_flags = 0;

	if (src->provider->nstat_counts(src->cookie, &counts.counts, gone) == 0) {
		if ((src->filter & NSTAT_FILTER_NOZEROBYTES) &&
		    counts.counts.nstat_rxbytes == 0 &&
		    counts.counts.nstat_txbytes == 0) {
			result = EAGAIN;
		} else {
			result = ctl_enqueuedata(state->ncs_kctl,
			    state->ncs_unit, &counts, sizeof(counts),
			    CTL_DATA_EOR);
			if (result != 0) {
				nstat_stats.nstat_sendcountfailures += 1;
			}
		}
	}
	return result;
}

static errno_t
nstat_control_append_counts(
	nstat_control_state *state,
	nstat_src           *src,
	int                 *gone)
{
	/* Some providers may not have any counts to send */
	if (!src->provider->nstat_counts) {
		return 0;
	}

	nstat_msg_src_counts counts;
	bzero(&counts, sizeof(counts));
	counts.hdr.type = NSTAT_MSG_TYPE_SRC_COUNTS;
	counts.hdr.length = sizeof(counts);
	counts.srcref = src->srcref;
	counts.event_flags = 0;

	errno_t result = 0;
	result = src->provider->nstat_counts(src->cookie, &counts.counts, gone);
	if (result != 0) {
		return result;
	}

	if ((src->filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
	    counts.counts.nstat_rxbytes == 0 && counts.counts.nstat_txbytes == 0) {
		return EAGAIN;
	}

	return nstat_accumulate_msg(state, &counts.hdr, counts.hdr.length);
}

static int
nstat_control_send_description(
	nstat_control_state *state,
	nstat_src           *src,
	u_int64_t           context,
	u_int16_t           hdr_flags)
{
	// Provider doesn't support getting the descriptor? Done.
	if (src->provider->nstat_descriptor_length == 0 ||
	    src->provider->nstat_copy_descriptor == NULL) {
		return EOPNOTSUPP;
	}

	// Allocate storage for the descriptor message
	mbuf_t          msg;
	unsigned int    one = 1;
	size_t          size = offsetof(nstat_msg_src_description, data) + src->provider->nstat_descriptor_length;
	assert(size <= MAX_NSTAT_MSG_HDR_LENGTH);

	if (mbuf_allocpacket(MBUF_DONTWAIT, size, &one, &msg) != 0) {
		return ENOMEM;
	}

	nstat_msg_src_description *desc = (nstat_msg_src_description*)mbuf_data(msg);
	bzero(desc, size);
	mbuf_setlen(msg, size);
	mbuf_pkthdr_setlen(msg, mbuf_len(msg));

	// Query the provider for the provider specific bits
	errno_t result = src->provider->nstat_copy_descriptor(src->cookie, desc->data, src->provider->nstat_descriptor_length);

	if (result != 0) {
		mbuf_freem(msg);
		return result;
	}

	desc->hdr.context = context;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_DESC;
	desc->hdr.length = (u_int16_t)size;
	desc->hdr.flags = hdr_flags;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, msg, CTL_DATA_EOR);
	if (result != 0) {
		nstat_stats.nstat_descriptionfailures += 1;
		mbuf_freem(msg);
	}

	return result;
}

static errno_t
nstat_control_append_description(
	nstat_control_state *state,
	nstat_src           *src)
{
	size_t  size = offsetof(nstat_msg_src_description, data) + src->provider->nstat_descriptor_length;
	if (size > 512 || src->provider->nstat_descriptor_length == 0 ||
	    src->provider->nstat_copy_descriptor == NULL) {
		return EOPNOTSUPP;
	}

	// Fill out a buffer on the stack, we will copy to the mbuf later
	u_int64_t buffer[size / sizeof(u_int64_t)  + 1]; // u_int64_t to ensure alignment
	bzero(buffer, size);

	nstat_msg_src_description *desc = (nstat_msg_src_description*)buffer;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_DESC;
	desc->hdr.length = (u_int16_t)size;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	errno_t result = 0;
	// Fill in the description
	// Query the provider for the provider specific bits
	result = src->provider->nstat_copy_descriptor(src->cookie, desc->data,
	    src->provider->nstat_descriptor_length);
	if (result != 0) {
		return result;
	}

	return nstat_accumulate_msg(state, &desc->hdr, size);
}

static uint64_t
nstat_extension_flags_for_source(
	nstat_control_state *state,
	nstat_src           *src)
{
	VERIFY(state != NULL & src != NULL);
	nstat_provider_id_t provider_id = src->provider->nstat_provider_id;

	return state->ncs_provider_filters[provider_id].npf_extensions;
}

static int
nstat_control_send_update(
	nstat_control_state *state,
	nstat_src           *src,
	u_int64_t           context,
	u_int64_t           event,
	u_int16_t           hdr_flags,
	int                 *gone)
{
	// Provider doesn't support getting the descriptor or counts? Done.
	if ((src->provider->nstat_descriptor_length == 0 ||
	    src->provider->nstat_copy_descriptor == NULL) &&
	    src->provider->nstat_counts == NULL) {
		return EOPNOTSUPP;
	}

	// Allocate storage for the descriptor message
	mbuf_t          msg;
	unsigned int    one = 1;
	size_t          size = offsetof(nstat_msg_src_update, data) +
	    src->provider->nstat_descriptor_length;
	size_t          total_extension_size = 0;
	u_int32_t       num_extensions = 0;
	u_int64_t       extension_mask = nstat_extension_flags_for_source(state, src);

	if ((extension_mask != 0) && (src->provider->nstat_copy_extension != NULL)) {
		uint32_t extension_id = 0;
		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				size_t extension_size = src->provider->nstat_copy_extension(src->cookie, extension_id, NULL, 0);
				if (extension_size == 0) {
					extension_mask &= ~(1ull << extension_id);
				} else {
					num_extensions++;
					total_extension_size += ROUNDUP64(extension_size);
				}
			}
		}
		size += total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * num_extensions);
	}
	assert(size <= MAX_NSTAT_MSG_HDR_LENGTH);

	/*
	 * XXX Would be interesting to see how extended updates affect mbuf
	 * allocations, given the max segments defined as 1, one may get
	 * allocations with higher fragmentation.
	 */
	if (mbuf_allocpacket(MBUF_DONTWAIT, size, &one, &msg) != 0) {
		return ENOMEM;
	}

	nstat_msg_src_update *desc = (nstat_msg_src_update*)mbuf_data(msg);
	bzero(desc, size);
	desc->hdr.context = context;
	desc->hdr.type = (num_extensions == 0) ? NSTAT_MSG_TYPE_SRC_UPDATE :
	    NSTAT_MSG_TYPE_SRC_EXTENDED_UPDATE;
	desc->hdr.length = (u_int16_t)size;
	desc->hdr.flags = hdr_flags;
	desc->srcref = src->srcref;
	desc->event_flags = event;
	desc->provider = src->provider->nstat_provider_id;

	/*
	 * XXX The following two lines are only valid when max-segments is passed
	 * as one.
	 * Other computations with offset also depend on that being true.
	 * Be aware of that before making any modifications that changes that
	 * behavior.
	 */
	mbuf_setlen(msg, size);
	mbuf_pkthdr_setlen(msg, mbuf_len(msg));

	errno_t result = 0;
	if (src->provider->nstat_descriptor_length != 0 && src->provider->nstat_copy_descriptor) {
		// Query the provider for the provider specific bits
		result = src->provider->nstat_copy_descriptor(src->cookie, desc->data,
		    src->provider->nstat_descriptor_length);
		if (result != 0) {
			mbuf_freem(msg);
			return result;
		}
	}

	if (num_extensions > 0) {
		nstat_msg_src_extended_item_hdr *p_extension_hdr = (nstat_msg_src_extended_item_hdr *)(void *)((char *)mbuf_data(msg) +
		    sizeof(nstat_msg_src_update_hdr) + src->provider->nstat_descriptor_length);
		uint32_t extension_id = 0;

		bzero(p_extension_hdr, total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * num_extensions));

		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				void *buf = (void *)(p_extension_hdr + 1);
				size_t extension_size = src->provider->nstat_copy_extension(src->cookie, extension_id, buf, total_extension_size);
				if ((extension_size == 0) || (extension_size > total_extension_size)) {
					// Something has gone wrong. Instead of attempting to wind back the excess buffer space, mark it as unused
					p_extension_hdr->type = NSTAT_EXTENDED_UPDATE_TYPE_UNKNOWN;
					p_extension_hdr->length = total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * (num_extensions - 1));
					break;
				} else {
					// The extension may be of any size alignment, reported as such in the extension header,
					// but we pad to ensure that whatever comes next is suitably aligned
					p_extension_hdr->type = extension_id;
					p_extension_hdr->length = extension_size;
					extension_size = ROUNDUP64(extension_size);
					total_extension_size -= extension_size;
					p_extension_hdr = (nstat_msg_src_extended_item_hdr *)(void *)((char *)buf + extension_size);
					num_extensions--;
				}
			}
		}
	}

	if (src->provider->nstat_counts) {
		result = src->provider->nstat_counts(src->cookie, &desc->counts, gone);
		if (result == 0) {
			if ((src->filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
			    desc->counts.nstat_rxbytes == 0 && desc->counts.nstat_txbytes == 0) {
				result = EAGAIN;
			} else {
				result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, msg, CTL_DATA_EOR);
			}
		}
	}

	if (result != 0) {
		nstat_stats.nstat_srcupatefailures += 1;
		mbuf_freem(msg);
	} else {
		src->ns_reported = true;
	}

	return result;
}

static errno_t
nstat_control_append_update(
	nstat_control_state *state,
	nstat_src           *src,
	int                 *gone)
{
	if ((src->provider->nstat_descriptor_length == 0 ||
	    src->provider->nstat_copy_descriptor == NULL) &&
	    src->provider->nstat_counts == NULL) {
		return EOPNOTSUPP;
	}

	size_t      size = offsetof(nstat_msg_src_update, data) + src->provider->nstat_descriptor_length;
	size_t      total_extension_size = 0;
	u_int32_t   num_extensions = 0;
	u_int64_t   extension_mask = nstat_extension_flags_for_source(state, src);

	if ((extension_mask != 0) && (src->provider->nstat_copy_extension != NULL)) {
		uint32_t extension_id = 0;
		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				size_t extension_size = src->provider->nstat_copy_extension(src->cookie, extension_id, NULL, 0);
				if (extension_size == 0) {
					extension_mask &= ~(1ull << extension_id);
				} else {
					num_extensions++;
					total_extension_size += ROUNDUP64(extension_size);
				}
			}
		}
		size += total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * num_extensions);
	}

	/*
	 * This kind of limits extensions.
	 * The optimization is around being able to deliver multiple
	 * of updates bundled together.
	 * Increasing the size runs the risk of too much stack usage.
	 * One could potentially changed the allocation below to be on heap.
	 * For now limiting it to half of NSTAT_MAX_MSG_SIZE.
	 */
	if (size > (NSTAT_MAX_MSG_SIZE >> 1)) {
		return EOPNOTSUPP;
	}

	// Fill out a buffer on the stack, we will copy to the mbuf later
	u_int64_t buffer[size / sizeof(u_int64_t)  + 1]; // u_int64_t to ensure alignment
	bzero(buffer, size);

	nstat_msg_src_update    *desc = (nstat_msg_src_update*)buffer;
	desc->hdr.type = (num_extensions == 0) ? NSTAT_MSG_TYPE_SRC_UPDATE :
	    NSTAT_MSG_TYPE_SRC_EXTENDED_UPDATE;
	desc->hdr.length = (u_int16_t)size;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	errno_t result = 0;
	// Fill in the description
	if (src->provider->nstat_descriptor_length != 0 && src->provider->nstat_copy_descriptor) {
		// Query the provider for the provider specific bits
		result = src->provider->nstat_copy_descriptor(src->cookie, desc->data,
		    src->provider->nstat_descriptor_length);
		if (result != 0) {
			nstat_stats.nstat_copy_descriptor_failures++;
			if (nstat_debug != 0) {
				printf("%s: src->provider->nstat_copy_descriptor: %d\n", __func__, result);
			}
			return result;
		}
	}

	if (num_extensions > 0) {
		nstat_msg_src_extended_item_hdr *p_extension_hdr = (nstat_msg_src_extended_item_hdr *)(void *)((char *)buffer +
		    sizeof(nstat_msg_src_update_hdr) + src->provider->nstat_descriptor_length);
		uint32_t extension_id = 0;
		bzero(p_extension_hdr, total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * num_extensions));

		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				void *buf = (void *)(p_extension_hdr + 1);
				size_t extension_size = src->provider->nstat_copy_extension(src->cookie, extension_id, buf, total_extension_size);
				if ((extension_size == 0) || (extension_size > total_extension_size)) {
					// Something has gone wrong. Instead of attempting to wind back the excess buffer space, mark it as unused
					p_extension_hdr->type = NSTAT_EXTENDED_UPDATE_TYPE_UNKNOWN;
					p_extension_hdr->length = total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * (num_extensions - 1));
					break;
				} else {
					extension_size = ROUNDUP64(extension_size);
					p_extension_hdr->type = extension_id;
					p_extension_hdr->length = extension_size;
					total_extension_size -= extension_size;
					p_extension_hdr = (nstat_msg_src_extended_item_hdr *)(void *)((char *)buf + extension_size);
					num_extensions--;
				}
			}
		}
	}

	if (src->provider->nstat_counts) {
		result = src->provider->nstat_counts(src->cookie, &desc->counts, gone);
		if (result != 0) {
			nstat_stats.nstat_provider_counts_failures++;
			if (nstat_debug != 0) {
				printf("%s: src->provider->nstat_counts: %d\n", __func__, result);
			}
			return result;
		}

		if ((src->filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
		    desc->counts.nstat_rxbytes == 0 && desc->counts.nstat_txbytes == 0) {
			return EAGAIN;
		}
	}

	result = nstat_accumulate_msg(state, &desc->hdr, size);
	if (result == 0) {
		src->ns_reported = true;
	}
	return result;
}

static errno_t
nstat_control_send_removed(
	nstat_control_state *state,
	nstat_src           *src,
	u_int16_t           hdr_flags)
{
	nstat_msg_src_removed removed;
	errno_t result;

	bzero(&removed, sizeof(removed));
	removed.hdr.type = NSTAT_MSG_TYPE_SRC_REMOVED;
	removed.hdr.length = sizeof(removed);
	removed.hdr.context = 0;
	removed.hdr.flags = hdr_flags;
	removed.srcref = src->srcref;
	result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, &removed,
	    sizeof(removed), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		nstat_stats.nstat_msgremovedfailures += 1;
	}

	return result;
}

static errno_t
nstat_control_handle_add_request(
	nstat_control_state *state,
	mbuf_t              m)
{
	errno_t result;

	// Verify the header fits in the first mbuf
	if (mbuf_len(m) < offsetof(nstat_msg_add_src_req, param)) {
		return EINVAL;
	}

	// Calculate the length of the parameter field
	ssize_t paramlength = mbuf_pkthdr_len(m) - offsetof(nstat_msg_add_src_req, param);
	if (paramlength < 0 || paramlength > 2 * 1024) {
		return EINVAL;
	}

	nstat_provider          *provider = NULL;
	nstat_provider_cookie_t cookie = NULL;
	nstat_msg_add_src_req   *req = mbuf_data(m);
	if (mbuf_pkthdr_len(m) > mbuf_len(m)) {
		// parameter is too large, we need to make a contiguous copy
		void *data = (void *) kalloc_data(paramlength, Z_WAITOK);

		if (!data) {
			return ENOMEM;
		}
		result = mbuf_copydata(m, offsetof(nstat_msg_add_src_req, param), paramlength, data);
		if (result == 0) {
			result = nstat_lookup_entry(req->provider, data, paramlength, &provider, &cookie);
		}
		kfree_data(data, paramlength);
	} else {
		result = nstat_lookup_entry(req->provider, (void*)&req->param, paramlength, &provider, &cookie);
	}

	if (result != 0) {
		return result;
	}

	// sanitize cookie
	nstat_control_sanitize_cookie(state, provider->nstat_provider_id, cookie);

	result = nstat_control_source_add(req->hdr.context, state, provider, cookie);
	if (result != 0) {
		provider->nstat_release(cookie, 0);
	}

	// Set the flag if a provider added a single source
	os_atomic_or(&state->ncs_added_src, (1 << provider->nstat_provider_id), relaxed);

	return result;
}

static errno_t
nstat_set_provider_filter(
	nstat_control_state     *state,
	nstat_msg_add_all_srcs  *req)
{
	nstat_provider_id_t provider_id = req->provider;

	u_int32_t prev_ncs_watching = os_atomic_or_orig(&state->ncs_watching, (1 << provider_id), relaxed);

	// Reject it if the client is already watching all the sources.
	if ((prev_ncs_watching & (1 << provider_id)) != 0) {
		return EALREADY;
	}

	// Reject it if any single source has already been added.
	u_int32_t ncs_added_src = os_atomic_load(&state->ncs_added_src, relaxed);
	if ((ncs_added_src & (1 << provider_id)) != 0) {
		return EALREADY;
	}

	state->ncs_watching |= (1 << provider_id);
	state->ncs_provider_filters[provider_id].npf_events = req->events;
	state->ncs_provider_filters[provider_id].npf_flags  = req->filter;
	state->ncs_provider_filters[provider_id].npf_pid    = req->target_pid;
	uuid_copy(state->ncs_provider_filters[provider_id].npf_uuid, req->target_uuid);

	// The extensions should be populated by a more direct mechanism
	// Using the top 32 bits of the filter flags reduces the namespace of both,
	// but is a convenient workaround that avoids ntstat.h changes that would require rebuild of all clients
	// Extensions give away additional privacy information and are subject to unconditional privilege check,
	// unconstrained by the value of nstat_privcheck
	if (priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) == 0) {
		state->ncs_provider_filters[provider_id].npf_extensions = (req->filter >> NSTAT_FILTER_ALLOWED_EXTENSIONS_SHIFT) & NSTAT_EXTENDED_UPDATE_FLAG_MASK;
	}
	return 0;
}

static errno_t
nstat_control_handle_add_all(
	nstat_control_state     *state,
	mbuf_t                  m)
{
	errno_t result = 0;

	// Verify the header fits in the first mbuf
	if (mbuf_len(m) < sizeof(nstat_msg_add_all_srcs)) {
		return EINVAL;
	}

	nstat_msg_add_all_srcs  *req = mbuf_data(m);
	if (req->provider > NSTAT_PROVIDER_LAST) {
		return ENOENT;
	}

	nstat_provider *provider = nstat_find_provider_by_id(req->provider);

	if (!provider) {
		return ENOENT;
	}
	if (provider->nstat_watcher_add == NULL) {
		return ENOTSUP;
	}

	// Traditionally the nstat_privcheck value allowed for easy access to ntstat on the Mac.
	// Keep backwards compatibility while being more stringent with recent providers
	if ((nstat_privcheck != 0) || (req->provider == NSTAT_PROVIDER_UDP_SUBFLOW) || (req->provider == NSTAT_PROVIDER_CONN_USERLAND)) {
		result = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);
		if (result != 0) {
			return result;
		}
	}

	lck_mtx_lock(&state->ncs_mtx);
	if (req->filter & NSTAT_FILTER_SUPPRESS_SRC_ADDED) {
		// Suppression of source messages implicitly requires the use of update messages
		state->ncs_flags |= NSTAT_FLAG_SUPPORTS_UPDATES;
	}
	lck_mtx_unlock(&state->ncs_mtx);

	// rdar://problem/30301300   Different providers require different synchronization
	// to ensure that a new entry does not get double counted due to being added prior
	// to all current provider entries being added.  Hence pass the provider the details
	// in the original request for this to be applied atomically

	result = provider->nstat_watcher_add(state, req);

	if (result == 0) {
		nstat_enqueue_success(req->hdr.context, state, 0);
	}

	return result;
}

static errno_t
nstat_control_source_add(
	u_int64_t               context,
	nstat_control_state     *state,
	nstat_provider          *provider,
	nstat_provider_cookie_t cookie)
{
	// Fill out source added message if appropriate
	mbuf_t                  msg = NULL;
	nstat_src_ref_t         *srcrefp = NULL;

	u_int64_t               provider_filter_flags =
	    state->ncs_provider_filters[provider->nstat_provider_id].npf_flags;
	boolean_t               tell_user =
	    ((provider_filter_flags & NSTAT_FILTER_SUPPRESS_SRC_ADDED) == 0);
	u_int32_t               src_filter =
	    (provider_filter_flags & NSTAT_FILTER_PROVIDER_NOZEROBYTES)
	    ? NSTAT_FILTER_NOZEROBYTES : 0;

	if (provider_filter_flags & NSTAT_FILTER_TCP_NO_EARLY_CLOSE) {
		src_filter |= NSTAT_FILTER_TCP_NO_EARLY_CLOSE;
	}

	if (tell_user) {
		unsigned int one = 1;

		if (mbuf_allocpacket(MBUF_DONTWAIT, sizeof(nstat_msg_src_added),
		    &one, &msg) != 0) {
			return ENOMEM;
		}

		mbuf_setlen(msg, sizeof(nstat_msg_src_added));
		mbuf_pkthdr_setlen(msg, mbuf_len(msg));
		nstat_msg_src_added     *add = mbuf_data(msg);
		bzero(add, sizeof(*add));
		add->hdr.type = NSTAT_MSG_TYPE_SRC_ADDED;
		assert(mbuf_len(msg) <= MAX_NSTAT_MSG_HDR_LENGTH);
		add->hdr.length = (u_int16_t)mbuf_len(msg);
		add->hdr.context = context;
		add->provider = provider->nstat_provider_id;
		srcrefp = &add->srcref;
	}

	// Allocate storage for the source
	nstat_src *src = kalloc_type(struct nstat_src, Z_WAITOK);
	if (src == NULL) {
		if (msg) {
			mbuf_freem(msg);
		}
		return ENOMEM;
	}

	// Fill in the source, including picking an unused source ref
	lck_mtx_lock(&state->ncs_mtx);

	src->srcref = nstat_control_next_src_ref(state);
	if (srcrefp) {
		*srcrefp = src->srcref;
	}

	if (state->ncs_flags & NSTAT_FLAG_CLEANUP || src->srcref == NSTAT_SRC_REF_INVALID) {
		lck_mtx_unlock(&state->ncs_mtx);
		kfree_type(struct nstat_src, src);
		if (msg) {
			mbuf_freem(msg);
		}
		return EINVAL;
	}
	src->provider = provider;
	src->cookie = cookie;
	src->filter = src_filter;
	src->seq = 0;

	if (msg) {
		// send the source added message if appropriate
		errno_t result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, msg,
		    CTL_DATA_EOR);
		if (result != 0) {
			nstat_stats.nstat_srcaddedfailures += 1;
			lck_mtx_unlock(&state->ncs_mtx);
			kfree_type(struct nstat_src, src);
			mbuf_freem(msg);
			return result;
		}
	}
	// Put the source in the list
	TAILQ_INSERT_HEAD(&state->ncs_src_queue, src, ns_control_link);
	src->ns_control = state;

	lck_mtx_unlock(&state->ncs_mtx);

	return 0;
}

static errno_t
nstat_control_handle_remove_request(
	nstat_control_state *state,
	mbuf_t              m)
{
	nstat_src_ref_t srcref = NSTAT_SRC_REF_INVALID;
	nstat_src *src;

	if (mbuf_copydata(m, offsetof(nstat_msg_rem_src_req, srcref), sizeof(srcref), &srcref) != 0) {
		return EINVAL;
	}

	lck_mtx_lock(&state->ncs_mtx);

	// Remove this source as we look for it
	TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
	{
		if (src->srcref == srcref) {
			break;
		}
	}
	if (src) {
		TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
	}

	lck_mtx_unlock(&state->ncs_mtx);

	if (src) {
		nstat_control_cleanup_source(state, src, FALSE);
	}

	return src ? 0 : ENOENT;
}

static errno_t
nstat_control_handle_query_request(
	nstat_control_state *state,
	mbuf_t              m)
{
	// TBD: handle this from another thread so we can enqueue a lot of data
	// As written, if a client requests query all, this function will be
	// called from their send of the request message. We will attempt to write
	// responses and succeed until the buffer fills up. Since the clients thread
	// is blocked on send, it won't be reading unless the client has two threads
	// using this socket, one for read and one for write. Two threads probably
	// won't work with this code anyhow since we don't have proper locking in
	// place yet.
	tailq_head_nstat_src    dead_list;
	errno_t                 result = ENOENT;
	nstat_msg_query_src_req req;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0) {
		return EINVAL;
	}

	TAILQ_INIT(&dead_list);
	const boolean_t  all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);

	lck_mtx_lock(&state->ncs_mtx);

	if (all_srcs) {
		state->ncs_flags |= NSTAT_FLAG_REQCOUNTS;
	}
	nstat_src       *src, *tmpsrc;
	u_int64_t       src_count = 0;
	boolean_t       partial = FALSE;

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_control_begin_query.
	 */
	partial = nstat_control_begin_query(state, &req.hdr);


	TAILQ_FOREACH_SAFE(src, &state->ncs_src_queue, ns_control_link, tmpsrc)
	{
		int     gone = 0;

		// XXX ignore IFACE types?
		if (all_srcs || src->srcref == req.srcref) {
			if (nstat_control_reporting_allowed(state, src, 0)
			    && (!partial || !all_srcs || src->seq != state->ncs_seq)) {
				if (all_srcs &&
				    (req.hdr.flags & NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE) != 0) {
					result = nstat_control_append_counts(state, src, &gone);
				} else {
					result = nstat_control_send_counts(state, src, req.hdr.context, 0, &gone);
				}

				if (ENOMEM == result || ENOBUFS == result) {
					/*
					 * If the counts message failed to
					 * enqueue then we should clear our flag so
					 * that a client doesn't miss anything on
					 * idle cleanup.  We skip the "gone"
					 * processing in the hope that we may
					 * catch it another time.
					 */
					state->ncs_flags &= ~NSTAT_FLAG_REQCOUNTS;
					break;
				}
				if (partial) {
					/*
					 * We skip over hard errors and
					 * filtered sources.
					 */
					src->seq = state->ncs_seq;
					src_count++;
				}
			}
		}

		if (gone) {
			// send one last descriptor message so client may see last state
			// If we can't send the notification now, it
			// will be sent in the idle cleanup.
			result = nstat_control_send_description(state, src, 0, 0);
			if (result != 0) {
				nstat_stats.nstat_control_send_description_failures++;
				if (nstat_debug != 0) {
					printf("%s - nstat_control_send_description() %d\n", __func__, result);
				}
				state->ncs_flags &= ~NSTAT_FLAG_REQCOUNTS;
				break;
			}

			// pull src out of the list
			TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
			TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
		}

		if (all_srcs) {
			if (src_count >= QUERY_CONTINUATION_SRC_COUNT) {
				break;
			}
		} else if (req.srcref == src->srcref) {
			break;
		}
	}

	nstat_flush_accumulated_msgs(state);

	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL) {
		flags = nstat_control_end_query(state, src, partial);
	}

	lck_mtx_unlock(&state->ncs_mtx);

	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_control_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result) {
		nstat_enqueue_success(req.hdr.context, state, flags);
		result = 0;
	}

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		nstat_control_cleanup_source(state, src, FALSE);
	}

	return result;
}

static errno_t
nstat_control_handle_get_src_description(
	nstat_control_state *state,
	mbuf_t              m)
{
	nstat_msg_get_src_description   req;
	errno_t result = ENOENT;
	nstat_src *src;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0) {
		return EINVAL;
	}

	lck_mtx_lock(&state->ncs_mtx);
	u_int64_t src_count = 0;
	boolean_t partial = FALSE;
	const boolean_t all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_control_begin_query.
	 */
	partial = nstat_control_begin_query(state, &req.hdr);

	TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
	{
		if (all_srcs || src->srcref == req.srcref) {
			if (nstat_control_reporting_allowed(state, src, 0)
			    && (!all_srcs || !partial || src->seq != state->ncs_seq)) {
				if ((req.hdr.flags & NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE) != 0 && all_srcs) {
					result = nstat_control_append_description(state, src);
				} else {
					result = nstat_control_send_description(state, src, req.hdr.context, 0);
				}

				if (ENOMEM == result || ENOBUFS == result) {
					/*
					 * If the description message failed to
					 * enqueue then we give up for now.
					 */
					break;
				}
				if (partial) {
					/*
					 * Note, we skip over hard errors and
					 * filtered sources.
					 */
					src->seq = state->ncs_seq;
					src_count++;
					if (src_count >= QUERY_CONTINUATION_SRC_COUNT) {
						break;
					}
				}
			}

			if (!all_srcs) {
				break;
			}
		}
	}
	nstat_flush_accumulated_msgs(state);

	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL) {
		flags = nstat_control_end_query(state, src, partial);
	}

	lck_mtx_unlock(&state->ncs_mtx);
	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_control_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result) {
		nstat_enqueue_success(req.hdr.context, state, flags);
		result = 0;
	}

	return result;
}

static errno_t
nstat_control_handle_set_filter(
	nstat_control_state *state,
	mbuf_t              m)
{
	nstat_msg_set_filter req;
	nstat_src *src;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0) {
		return EINVAL;
	}
	if (req.srcref == NSTAT_SRC_REF_ALL ||
	    req.srcref == NSTAT_SRC_REF_INVALID) {
		return EINVAL;
	}

	lck_mtx_lock(&state->ncs_mtx);
	TAILQ_FOREACH(src, &state->ncs_src_queue, ns_control_link)
	{
		if (req.srcref == src->srcref) {
			src->filter = req.filter;
			break;
		}
	}
	lck_mtx_unlock(&state->ncs_mtx);
	if (src == NULL) {
		return ENOENT;
	}

	return 0;
}

static void
nstat_send_error(
	nstat_control_state *state,
	u_int64_t context,
	u_int32_t error)
{
	errno_t result;
	struct nstat_msg_error  err;

	bzero(&err, sizeof(err));
	err.hdr.type = NSTAT_MSG_TYPE_ERROR;
	err.hdr.length = sizeof(err);
	err.hdr.context = context;
	err.error = error;

	result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, &err,
	    sizeof(err), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		nstat_stats.nstat_msgerrorfailures++;
	}
}

static boolean_t
nstat_control_begin_query(
	nstat_control_state *state,
	const nstat_msg_hdr *hdrp)
{
	boolean_t partial = FALSE;

	if (hdrp->flags & NSTAT_MSG_HDR_FLAG_CONTINUATION) {
		/* A partial query all has been requested. */
		partial = TRUE;

		if (state->ncs_context != hdrp->context) {
			if (state->ncs_context != 0) {
				nstat_send_error(state, state->ncs_context, EAGAIN);
			}

			/* Initialize state for a partial query all. */
			state->ncs_context = hdrp->context;
			state->ncs_seq++;
		}
	}

	return partial;
}

static u_int16_t
nstat_control_end_query(
	nstat_control_state *state,
	nstat_src *last_src,
	boolean_t partial)
{
	u_int16_t flags = 0;

	if (last_src == NULL || !partial) {
		/*
		 * We iterated through the entire srcs list or exited early
		 * from the loop when a partial update was not requested (an
		 * error occurred), so clear context to indicate internally
		 * that the query is finished.
		 */
		state->ncs_context = 0;
	} else {
		/*
		 * Indicate to userlevel to make another partial request as
		 * there are still sources left to be reported.
		 */
		flags |= NSTAT_MSG_HDR_FLAG_CONTINUATION;
	}

	return flags;
}

static errno_t
nstat_control_handle_get_update(
	nstat_control_state         *state,
	mbuf_t                      m)
{
	nstat_msg_query_src_req req;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0) {
		return EINVAL;
	}

	lck_mtx_lock(&state->ncs_mtx);

	state->ncs_flags |= NSTAT_FLAG_SUPPORTS_UPDATES;

	errno_t         result = ENOENT;
	nstat_src       *src, *tmpsrc;
	tailq_head_nstat_src dead_list;
	u_int64_t src_count = 0;
	boolean_t partial = FALSE;
	const boolean_t all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);
	TAILQ_INIT(&dead_list);

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_control_begin_query.
	 */
	partial = nstat_control_begin_query(state, &req.hdr);

	TAILQ_FOREACH_SAFE(src, &state->ncs_src_queue, ns_control_link, tmpsrc) {
		int gone = 0;
		if (all_srcs) {
			// Check to see if we should handle this source or if we're still skipping to find where to continue
			if ((FALSE == partial || src->seq != state->ncs_seq)) {
				u_int64_t suppression_flags = (src->ns_reported)? NSTAT_FILTER_SUPPRESS_BORING_POLL: 0;
				if (nstat_control_reporting_allowed(state, src, suppression_flags)) {
					result = nstat_control_append_update(state, src, &gone);
					if (ENOMEM == result || ENOBUFS == result) {
						/*
						 * If the update message failed to
						 * enqueue then give up.
						 */
						break;
					}
					if (partial) {
						/*
						 * We skip over hard errors and
						 * filtered sources.
						 */
						src->seq = state->ncs_seq;
						src_count++;
					}
				}
			}
		} else if (src->srcref == req.srcref) {
			if (nstat_control_reporting_allowed(state, src, 0)) {
				result = nstat_control_send_update(state, src, req.hdr.context, 0, 0, &gone);
			}
		}

		if (gone) {
			// pull src out of the list
			TAILQ_REMOVE(&state->ncs_src_queue, src, ns_control_link);
			TAILQ_INSERT_TAIL(&dead_list, src, ns_control_link);
		}

		if (!all_srcs && req.srcref == src->srcref) {
			break;
		}
		if (src_count >= QUERY_CONTINUATION_SRC_COUNT) {
			break;
		}
	}

	nstat_flush_accumulated_msgs(state);


	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL) {
		flags = nstat_control_end_query(state, src, partial);
	}

	lck_mtx_unlock(&state->ncs_mtx);
	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_control_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result) {
		nstat_enqueue_success(req.hdr.context, state, flags);
		result = 0;
	}

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, ns_control_link);
		// release src and send notification
		nstat_control_cleanup_source(state, src, FALSE);
	}

	return result;
}

static errno_t
nstat_control_handle_subscribe_sysinfo(
	nstat_control_state         *state)
{
	errno_t result = priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);

	if (result != 0) {
		return result;
	}

	lck_mtx_lock(&state->ncs_mtx);
	state->ncs_flags |= NSTAT_FLAG_SYSINFO_SUBSCRIBED;
	lck_mtx_unlock(&state->ncs_mtx);

	return 0;
}

static errno_t
nstat_control_send(
	kern_ctl_ref    kctl,
	u_int32_t       unit,
	void            *uinfo,
	mbuf_t          m,
	__unused int    flags)
{
	nstat_control_state     *state = (nstat_control_state*)uinfo;
	struct nstat_msg_hdr    *hdr;
	struct nstat_msg_hdr    storage;
	errno_t                                 result = 0;

	if (mbuf_pkthdr_len(m) < sizeof(*hdr)) {
		// Is this the right thing to do?
		mbuf_freem(m);
		return EINVAL;
	}

	if (mbuf_len(m) >= sizeof(*hdr)) {
		hdr = mbuf_data(m);
	} else {
		mbuf_copydata(m, 0, sizeof(storage), &storage);
		hdr = &storage;
	}

	// Legacy clients may not set the length
	// Those clients are likely not setting the flags either
	// Fix everything up so old clients continue to work
	if (hdr->length != mbuf_pkthdr_len(m)) {
		hdr->flags = 0;
		assert(mbuf_pkthdr_len(m) <= MAX_NSTAT_MSG_HDR_LENGTH);
		hdr->length = (u_int16_t)mbuf_pkthdr_len(m);
		if (hdr == &storage) {
			mbuf_copyback(m, 0, sizeof(*hdr), hdr, MBUF_DONTWAIT);
		}
	}

	switch (hdr->type) {
	case NSTAT_MSG_TYPE_ADD_SRC:
		result = nstat_control_handle_add_request(state, m);
		break;

	case NSTAT_MSG_TYPE_ADD_ALL_SRCS:
		result = nstat_control_handle_add_all(state, m);
		break;

	case NSTAT_MSG_TYPE_REM_SRC:
		result = nstat_control_handle_remove_request(state, m);
		break;

	case NSTAT_MSG_TYPE_QUERY_SRC:
		result = nstat_control_handle_query_request(state, m);
		break;

	case NSTAT_MSG_TYPE_GET_SRC_DESC:
		result = nstat_control_handle_get_src_description(state, m);
		break;

	case NSTAT_MSG_TYPE_SET_FILTER:
		result = nstat_control_handle_set_filter(state, m);
		break;

	case NSTAT_MSG_TYPE_GET_UPDATE:
		result = nstat_control_handle_get_update(state, m);
		break;

	case NSTAT_MSG_TYPE_SUBSCRIBE_SYSINFO:
		result = nstat_control_handle_subscribe_sysinfo(state);
		break;

	default:
		result = EINVAL;
		break;
	}

	if (result != 0) {
		struct nstat_msg_error  err;

		bzero(&err, sizeof(err));
		err.hdr.type = NSTAT_MSG_TYPE_ERROR;
		err.hdr.length = (u_int16_t)(sizeof(err) + mbuf_pkthdr_len(m));
		err.hdr.context = hdr->context;
		err.error = result;

		if (mbuf_prepend(&m, sizeof(err), MBUF_DONTWAIT) == 0 &&
		    mbuf_copyback(m, 0, sizeof(err), &err, MBUF_DONTWAIT) == 0) {
			result = ctl_enqueuembuf(kctl, unit, m, CTL_DATA_EOR | CTL_DATA_CRIT);
			if (result != 0) {
				mbuf_freem(m);
			}
			m = NULL;
		}

		if (result != 0) {
			// Unable to prepend the error to the request - just send the error
			err.hdr.length = sizeof(err);
			result = ctl_enqueuedata(kctl, unit, &err, sizeof(err),
			    CTL_DATA_EOR | CTL_DATA_CRIT);
			if (result != 0) {
				nstat_stats.nstat_msgerrorfailures += 1;
			}
		}
		nstat_stats.nstat_handle_msg_failures += 1;
	}

	if (m) {
		mbuf_freem(m);
	}

	return result;
}


/* Performs interface matching based on NSTAT_IFNET_IS… filter flags provided by an external caller */
static bool
nstat_interface_matches_filter_flag(uint32_t filter_flags, struct ifnet *ifp)
{
	bool result = false;

	if (ifp) {
		uint32_t flag_mask = (NSTAT_FILTER_IFNET_FLAGS & ~(NSTAT_IFNET_IS_NON_LOCAL | NSTAT_IFNET_IS_LOCAL));
		filter_flags &= flag_mask;

		uint32_t flags = nstat_ifnet_to_flags_extended(ifp);
		if (filter_flags & flags) {
			result = true;
		}
	}
	return result;
}


static int
tcp_progress_indicators_for_interface(unsigned int ifindex, uint64_t recentflow_maxduration, uint32_t filter_flags, struct xtcpprogress_indicators *indicators)
{
	int error = 0;
	struct inpcb *inp;
	uint64_t min_recent_start_time;
#if SKYWALK
	struct nstat_tu_shadow *shad;
#endif /* SKYWALK */

	min_recent_start_time = mach_continuous_time() - recentflow_maxduration;
	bzero(indicators, sizeof(*indicators));

#if NSTAT_DEBUG
	/* interface index -1 may be passed in to only match against the filters specified in the flags */
	if (ifindex < UINT_MAX) {
		printf("%s - for interface index %u with flags %x\n", __func__, ifindex, filter_flags);
	} else {
		printf("%s - for matching interface with flags %x\n", __func__, filter_flags);
	}
#endif

	lck_rw_lock_shared(&tcbinfo.ipi_lock);
	/*
	 * For progress indicators we don't need to special case TCP to collect time wait connections
	 */
	LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list)
	{
		struct tcpcb  *tp = intotcpcb(inp);
		/* radar://57100452
		 * The conditional logic implemented below performs an *inclusive* match based on the desired interface index in addition to any filter values.
		 * While the general expectation is that only one criteria normally is used for queries, the capability exists satisfy any eccentric future needs.
		 */
		if (tp &&
		    inp->inp_state != INPCB_STATE_DEAD &&
		    inp->inp_last_outifp &&
		    /* matches the given interface index, or against any provided filter flags */
		    (((inp->inp_last_outifp->if_index == ifindex) ||
		    nstat_interface_matches_filter_flag(filter_flags, inp->inp_last_outifp)) &&
		    /* perform flow state matching based any provided filter flags */
		    (((filter_flags & (NSTAT_IFNET_IS_NON_LOCAL | NSTAT_IFNET_IS_LOCAL)) == 0) ||
		    ((filter_flags & NSTAT_IFNET_IS_NON_LOCAL) && !(tp->t_flags & TF_LOCAL)) ||
		    ((filter_flags & NSTAT_IFNET_IS_LOCAL) && (tp->t_flags & TF_LOCAL))))) {
			struct tcp_conn_status connstatus;
#if NSTAT_DEBUG
			printf("%s - *matched non-Skywalk* [filter match: %d]\n", __func__, nstat_interface_matches_filter_flag(filter_flags, inp->inp_last_outifp));
#endif
			indicators->xp_numflows++;
			tcp_get_connectivity_status(tp, &connstatus);
			if (connstatus.write_probe_failed) {
				indicators->xp_write_probe_fails++;
			}
			if (connstatus.read_probe_failed) {
				indicators->xp_read_probe_fails++;
			}
			if (connstatus.conn_probe_failed) {
				indicators->xp_conn_probe_fails++;
			}
			if (inp->inp_start_timestamp > min_recent_start_time) {
				uint64_t flow_count;

				indicators->xp_recentflows++;
				flow_count = os_atomic_load(&inp->inp_stat->rxbytes, relaxed);
				indicators->xp_recentflows_rxbytes += flow_count;
				flow_count = os_atomic_load(&inp->inp_stat->txbytes, relaxed);
				indicators->xp_recentflows_txbytes += flow_count;

				indicators->xp_recentflows_rxooo += tp->t_stat.rxoutoforderbytes;
				indicators->xp_recentflows_rxdup += tp->t_stat.rxduplicatebytes;
				indicators->xp_recentflows_retx += tp->t_stat.txretransmitbytes;
				if (tp->snd_max - tp->snd_una) {
					indicators->xp_recentflows_unacked++;
				}
			}
		}
	}
	lck_rw_done(&tcbinfo.ipi_lock);

#if SKYWALK
	lck_mtx_lock(&nstat_mtx);

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if ((shad->shad_provider == NSTAT_PROVIDER_TCP_USERLAND) && (shad->shad_live)) {
			u_int16_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
			u_int32_t extended_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
			if (filter_flags != 0) {
				bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL);
				error = (result)? 0 : EIO;
				if (error) {
					printf("%s - nstat get ifflags %d\n", __func__, error);
					continue;
				}
				extended_ifflags = extend_ifnet_flags(ifflags);

				if ((extended_ifflags & filter_flags) == 0) {
					continue;
				}
				// Skywalk locality flags are not yet in place, see <rdar://problem/35607563>
				// Instead of checking flags with a simple logical and, check the inverse.
				// This allows for default action of fallthrough if the flags are not set.
				if ((filter_flags & NSTAT_IFNET_IS_NON_LOCAL) && (ifflags & NSTAT_IFNET_IS_LOCAL)) {
					continue;
				}
				if ((filter_flags & NSTAT_IFNET_IS_LOCAL) && (ifflags & NSTAT_IFNET_IS_NON_LOCAL)) {
					continue;
				}
			}

			nstat_progress_digest digest;
			bzero(&digest, sizeof(digest));
			bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, &digest, NULL, NULL);

			error = (result)? 0 : EIO;
			if (error) {
				printf("%s - nstat get progressdigest returned %d\n", __func__, error);
				continue;
			}
			if ((digest.ifindex == (u_int32_t)ifindex) ||
			    (filter_flags & extended_ifflags)) {
#if NSTAT_DEBUG
				printf("%s - *matched Skywalk* [filter match: %x %x]\n", __func__, filter_flags, extended_flags);
#endif
				indicators->xp_numflows++;
				if (digest.connstatus.write_probe_failed) {
					indicators->xp_write_probe_fails++;
				}
				if (digest.connstatus.read_probe_failed) {
					indicators->xp_read_probe_fails++;
				}
				if (digest.connstatus.conn_probe_failed) {
					indicators->xp_conn_probe_fails++;
				}
				if (shad->shad_start_timestamp > min_recent_start_time) {
					indicators->xp_recentflows++;
					indicators->xp_recentflows_rxbytes += digest.rxbytes;
					indicators->xp_recentflows_txbytes += digest.txbytes;
					indicators->xp_recentflows_rxooo += digest.rxoutoforderbytes;
					indicators->xp_recentflows_rxdup += digest.rxduplicatebytes;
					indicators->xp_recentflows_retx += digest.txretransmit;
					if (digest.txunacked) {
						indicators->xp_recentflows_unacked++;
					}
				}
			}
		}
	}

	lck_mtx_unlock(&nstat_mtx);

#endif /* SKYWALK */
	return error;
}


static int
tcp_progress_probe_enable_for_interface(unsigned int ifindex, uint32_t filter_flags, uint32_t enable_flags)
{
	int error = 0;
	struct ifnet *ifp;

#if NSTAT_DEBUG
	printf("%s - for interface index %u with flags %d\n", __func__, ifindex, filter_flags);
#endif

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
	{
		if ((ifp->if_index == ifindex) ||
		    nstat_interface_matches_filter_flag(filter_flags, ifp)) {
#if NSTAT_DEBUG
			printf("%s - *matched* interface index %d, enable: %d\n", __func__, ifp->if_index, enable_flags);
#endif
			error = if_probe_connectivity(ifp, enable_flags);
			if (error) {
				printf("%s (%d) - nstat set tcp probe %d for interface index %d\n", __func__, error, enable_flags, ifp->if_index);
			}
		}
	}
	ifnet_head_done();

	return error;
}


__private_extern__ int
ntstat_tcp_progress_indicators(struct sysctl_req *req)
{
	struct xtcpprogress_indicators indicators = {};
	int error = 0;
	struct tcpprogressreq requested;

	if (priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) != 0) {
		return EACCES;
	}
	if (req->newptr == USER_ADDR_NULL) {
		return EINVAL;
	}
	if (req->newlen < sizeof(req)) {
		return EINVAL;
	}
	error = SYSCTL_IN(req, &requested, sizeof(requested));
	if (error != 0) {
		return error;
	}
	error = tcp_progress_indicators_for_interface((unsigned int)requested.ifindex, requested.recentflow_maxduration, (uint32_t)requested.filter_flags, &indicators);
	if (error != 0) {
		return error;
	}
	error = SYSCTL_OUT(req, &indicators, sizeof(indicators));

	return error;
}


__private_extern__ int
ntstat_tcp_progress_enable(struct sysctl_req *req)
{
	int error = 0;
	struct tcpprobereq requested;

	if (priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) != 0) {
		return EACCES;
	}
	if (req->newptr == USER_ADDR_NULL) {
		return EINVAL;
	}
	if (req->newlen < sizeof(req)) {
		return EINVAL;
	}
	error = SYSCTL_IN(req, &requested, sizeof(requested));
	if (error != 0) {
		return error;
	}
	error = tcp_progress_probe_enable_for_interface((unsigned int)requested.ifindex, (uint32_t)requested.filter_flags, (uint32_t)requested.enable);

	return error;
}


#if SKYWALK

#pragma mark -- netstat support for user level providers --

typedef struct nstat_flow_data {
	nstat_counts        counts;
	union {
		nstat_udp_descriptor    udp_descriptor;
		nstat_tcp_descriptor    tcp_descriptor;
	} flow_descriptor;
} nstat_flow_data;

static int
nstat_gather_flow_data(nstat_provider_id_t provider, nstat_flow_data *flow_data, int n)
{
	struct nstat_tu_shadow *shad;
	int prepared = 0;
	errno_t err;

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if ((shad->shad_provider == provider) && (shad->shad_live)) {
			if (prepared >= n) {
				break;
			}
			err = nstat_userland_tu_copy_descriptor((nstat_provider_cookie_t) shad,
			    &flow_data->flow_descriptor, sizeof(flow_data->flow_descriptor));

			if (err != 0) {
				printf("%s - nstat_userland_tu_copy_descriptor  returned %d\n", __func__, err);
			}
			err = nstat_userland_tu_counts((nstat_provider_cookie_t) shad,
			    &flow_data->counts, NULL);
			if (err != 0) {
				printf("%s - nstat_userland_tu_counts  returned %d\n", __func__, err);
			}
			flow_data++;
			prepared++;
		}
	}
	return prepared;
}

static void
nstat_userland_to_xinpcb_n(nstat_provider_id_t provider, nstat_flow_data *flow_data, struct xinpcb_n *xinp)
{
	xinp->xi_len = sizeof(struct xinpcb_n);
	xinp->xi_kind = XSO_INPCB;

	if (provider == NSTAT_PROVIDER_TCP_USERLAND) {
		nstat_tcp_descriptor *desc = &flow_data->flow_descriptor.tcp_descriptor;
		struct sockaddr_in *sa = &desc->local.v4;
		if (sa->sin_family == AF_INET) {
			xinp->inp_vflag = INP_IPV4;
			xinp->inp_laddr = desc->local.v4.sin_addr;
			xinp->inp_lport = desc->local.v4.sin_port;
			xinp->inp_faddr = desc->remote.v4.sin_addr;
			xinp->inp_fport = desc->remote.v4.sin_port;
		} else if (sa->sin_family == AF_INET6) {
			xinp->inp_vflag = INP_IPV6;
			xinp->in6p_laddr = desc->local.v6.sin6_addr;
			xinp->in6p_lport = desc->local.v6.sin6_port;
			xinp->in6p_faddr = desc->remote.v6.sin6_addr;
			xinp->in6p_fport = desc->remote.v6.sin6_port;
		}
	} else if (provider == NSTAT_PROVIDER_UDP_USERLAND) {
		nstat_udp_descriptor *desc = &flow_data->flow_descriptor.udp_descriptor;
		struct sockaddr_in *sa = &desc->local.v4;
		if (sa->sin_family == AF_INET) {
			xinp->inp_vflag = INP_IPV4;
			xinp->inp_laddr = desc->local.v4.sin_addr;
			xinp->inp_lport = desc->local.v4.sin_port;
			xinp->inp_faddr = desc->remote.v4.sin_addr;
			xinp->inp_fport = desc->remote.v4.sin_port;
		} else if (sa->sin_family == AF_INET6) {
			xinp->inp_vflag = INP_IPV6;
			xinp->in6p_laddr = desc->local.v6.sin6_addr;
			xinp->in6p_lport = desc->local.v6.sin6_port;
			xinp->in6p_faddr = desc->remote.v6.sin6_addr;
			xinp->in6p_fport = desc->remote.v6.sin6_port;
		}
	}
}

static void
nstat_userland_to_xsocket_n(nstat_provider_id_t provider, nstat_flow_data *flow_data, struct xsocket_n *xso)
{
	xso->xso_len = sizeof(struct xsocket_n);
	xso->xso_kind = XSO_SOCKET;

	if (provider == NSTAT_PROVIDER_TCP_USERLAND) {
		nstat_tcp_descriptor *desc = &flow_data->flow_descriptor.tcp_descriptor;
		xso->xso_protocol = IPPROTO_TCP;
		xso->so_e_pid = desc->epid;
		xso->so_last_pid = desc->pid;
	} else {
		nstat_udp_descriptor *desc = &flow_data->flow_descriptor.udp_descriptor;
		xso->xso_protocol = IPPROTO_UDP;
		xso->so_e_pid = desc->epid;
		xso->so_last_pid = desc->pid;
	}
}

static void
nstat_userland_to_rcv_xsockbuf_n(nstat_provider_id_t provider, nstat_flow_data *flow_data, struct xsockbuf_n *xsbrcv)
{
	xsbrcv->xsb_len = sizeof(struct xsockbuf_n);
	xsbrcv->xsb_kind = XSO_RCVBUF;

	if (provider == NSTAT_PROVIDER_TCP_USERLAND) {
		nstat_tcp_descriptor *desc = &flow_data->flow_descriptor.tcp_descriptor;
		xsbrcv->sb_hiwat = desc->rcvbufsize;
		xsbrcv->sb_cc = desc->rcvbufused;
	} else {
		nstat_udp_descriptor *desc = &flow_data->flow_descriptor.udp_descriptor;
		xsbrcv->sb_hiwat = desc->rcvbufsize;
		xsbrcv->sb_cc = desc->rcvbufused;
	}
}

static void
nstat_userland_to_snd_xsockbuf_n(nstat_provider_id_t provider, nstat_flow_data *flow_data, struct xsockbuf_n *xsbsnd)
{
	xsbsnd->xsb_len = sizeof(struct xsockbuf_n);
	xsbsnd->xsb_kind = XSO_SNDBUF;

	if (provider == NSTAT_PROVIDER_TCP_USERLAND) {
		nstat_tcp_descriptor *desc = &flow_data->flow_descriptor.tcp_descriptor;
		xsbsnd->sb_hiwat = desc->sndbufsize;
		xsbsnd->sb_cc = desc->sndbufused;
	} else {
	}
}

static void
nstat_userland_to_xsockstat_n(nstat_flow_data *flow_data, struct xsockstat_n *xst)
{
	xst->xst_len = sizeof(struct xsockstat_n);
	xst->xst_kind = XSO_STATS;

	// The kernel version supports an array of counts, here we only support one and map to first entry
	xst->xst_tc_stats[0].rxpackets = flow_data->counts.nstat_rxpackets;
	xst->xst_tc_stats[0].rxbytes   = flow_data->counts.nstat_rxbytes;
	xst->xst_tc_stats[0].txpackets = flow_data->counts.nstat_txpackets;
	xst->xst_tc_stats[0].txbytes   = flow_data->counts.nstat_txbytes;
}

static void
nstat_userland_to_xtcpcb_n(nstat_flow_data *flow_data, struct  xtcpcb_n *xt)
{
	nstat_tcp_descriptor *desc = &flow_data->flow_descriptor.tcp_descriptor;
	xt->xt_len = sizeof(struct xtcpcb_n);
	xt->xt_kind = XSO_TCPCB;
	xt->t_state = desc->state;
	xt->snd_wnd = desc->txwindow;
	xt->snd_cwnd = desc->txcwindow;
}


__private_extern__ int
ntstat_userland_count(short proto)
{
	int n = 0;
	if (proto == IPPROTO_TCP) {
		n = nstat_userland_tcp_shadows;
	} else if (proto == IPPROTO_UDP) {
		n = nstat_userland_udp_shadows;
	}
	return n;
}

__private_extern__ int
nstat_userland_get_snapshot(short proto, void **snapshotp, int *countp)
{
	int error = 0;
	int n = 0;
	nstat_provider_id_t provider;
	nstat_flow_data *flow_data = NULL;

	lck_mtx_lock(&nstat_mtx);
	if (proto == IPPROTO_TCP) {
		n = nstat_userland_tcp_shadows;
		provider = NSTAT_PROVIDER_TCP_USERLAND;
	} else if (proto == IPPROTO_UDP) {
		n = nstat_userland_udp_shadows;
		provider = NSTAT_PROVIDER_UDP_USERLAND;
	}
	if (n == 0) {
		goto done;
	}

	flow_data = (nstat_flow_data *) kalloc_data(n * sizeof(*flow_data),
	    Z_WAITOK | Z_ZERO);
	if (flow_data) {
		n = nstat_gather_flow_data(provider, flow_data, n);
	} else {
		error = ENOMEM;
	}
done:
	lck_mtx_unlock(&nstat_mtx);
	*snapshotp = flow_data;
	*countp = n;
	return error;
}

// nstat_userland_list_snapshot() does most of the work for a sysctl that uses a return format
// as per get_pcblist_n() even though the vast majority of fields are unused.
// Additional items are required in the sysctl output before and after the data added
// by this function.
__private_extern__ int
nstat_userland_list_snapshot(short proto, struct sysctl_req *req, void *userlandsnapshot, int n)
{
	int error = 0;
	int i;
	nstat_provider_id_t provider;
	void *buf = NULL;
	nstat_flow_data *flow_data, *flow_data_array = NULL;
	size_t item_size = ROUNDUP64(sizeof(struct xinpcb_n)) +
	    ROUNDUP64(sizeof(struct xsocket_n)) +
	    2 * ROUNDUP64(sizeof(struct xsockbuf_n)) +
	    ROUNDUP64(sizeof(struct xsockstat_n));

	if ((n == 0) || (userlandsnapshot == NULL)) {
		goto done;
	}

	if (proto == IPPROTO_TCP) {
		item_size += ROUNDUP64(sizeof(struct xtcpcb_n));
		provider = NSTAT_PROVIDER_TCP_USERLAND;
	} else if (proto == IPPROTO_UDP) {
		provider = NSTAT_PROVIDER_UDP_USERLAND;
	} else {
		error = EINVAL;
		goto done;
	}

	buf = (void *) kalloc_data(item_size, Z_WAITOK);
	if (buf) {
		struct xinpcb_n *xi = (struct xinpcb_n *)buf;
		struct xsocket_n *xso = (struct xsocket_n *) ADVANCE64(xi, sizeof(*xi));
		struct xsockbuf_n *xsbrcv = (struct xsockbuf_n *) ADVANCE64(xso, sizeof(*xso));
		struct xsockbuf_n *xsbsnd = (struct xsockbuf_n *) ADVANCE64(xsbrcv, sizeof(*xsbrcv));
		struct xsockstat_n *xsostats = (struct xsockstat_n *) ADVANCE64(xsbsnd, sizeof(*xsbsnd));
		struct  xtcpcb_n *xt = (struct xtcpcb_n *) ADVANCE64(xsostats, sizeof(*xsostats));

		flow_data_array = (nstat_flow_data *)userlandsnapshot;

		for (i = 0; i < n; i++) {
			flow_data = &flow_data_array[i];
			bzero(buf, item_size);

			nstat_userland_to_xinpcb_n(provider, flow_data, xi);
			nstat_userland_to_xsocket_n(provider, flow_data, xso);
			nstat_userland_to_rcv_xsockbuf_n(provider, flow_data, xsbrcv);
			nstat_userland_to_snd_xsockbuf_n(provider, flow_data, xsbsnd);
			nstat_userland_to_xsockstat_n(flow_data, xsostats);
			if (proto == IPPROTO_TCP) {
				nstat_userland_to_xtcpcb_n(flow_data, xt);
			}
			error = SYSCTL_OUT(req, buf, item_size);
			if (error) {
				break;
			}
		}
		kfree_data(buf, item_size);
	} else {
		error = ENOMEM;
	}
done:
	return error;
}

__private_extern__ void
nstat_userland_release_snapshot(void *snapshot, int nuserland)
{
	if (snapshot != NULL) {
		kfree_data(snapshot, nuserland * sizeof(nstat_flow_data));
	}
}

#if NTSTAT_SUPPORTS_STANDALONE_SYSCTL

__private_extern__ int
ntstat_userland_list_n(short proto, struct sysctl_req *req)
{
	int error = 0;
	int n;
	struct xinpgen xig;
	void *snapshot = NULL;
	size_t item_size = ROUNDUP64(sizeof(struct xinpcb_n)) +
	    ROUNDUP64(sizeof(struct xsocket_n)) +
	    2 * ROUNDUP64(sizeof(struct xsockbuf_n)) +
	    ROUNDUP64(sizeof(struct xsockstat_n));

	if (proto == IPPROTO_TCP) {
		item_size += ROUNDUP64(sizeof(struct xtcpcb_n));
	}

	if (req->oldptr == USER_ADDR_NULL) {
		n = ntstat_userland_count(proto);
		req->oldidx = 2 * (sizeof(xig)) + (n + 1 + n / 8) * item_size;
		goto done;
	}

	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto done;
	}

	error = nstat_userland_get_snapshot(proto, &snapshot, &n);

	if (error) {
		goto done;
	}

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof(xig);
	xig.xig_gen = 0;
	xig.xig_sogen = 0;
	xig.xig_count = n;
	error = SYSCTL_OUT(req, &xig, sizeof(xig));
	if (error) {
		goto done;
	}
	/*
	 * We are done if there are no flows
	 */
	if (n == 0) {
		goto done;
	}

	error = nstat_userland_list_snapshot(proto, req, snapshot, n);

	if (!error) {
		/*
		 * Give the user an updated idea of our state,
		 * which is unchanged
		 */
		error = SYSCTL_OUT(req, &xig, sizeof(xig));
	}
done:
	nstat_userland_release_snapshot(snapshot, n);
	return error;
}

#endif /* NTSTAT_SUPPORTS_STANDALONE_SYSCTL */
#endif /* SKYWALK */
