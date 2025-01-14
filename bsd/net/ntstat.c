/*
 * Copyright (c) 2010-2024 Apple Inc. All rights reserved.
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
#include <sys/random.h>
#include <kern/clock.h>
#include <kern/debug.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/locks.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/route_private.h>
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

#include <net/sockaddr_utils.h>

__private_extern__ int  nstat_collect = 1;

#define NSTAT_TRACE_ENABLED                 0
#define NSTAT_FUZZ_TIMING                   0


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

static int ntstat_progress_indicators(struct sysctl_req *);
static struct net_api_stats net_api_stats_before;
static u_int64_t net_api_stats_last_report_time;
#define NET_API_STATS_REPORT_INTERVAL (12 * 60 * 60) /* 12 hours, in seconds */
static u_int32_t net_api_stats_report_interval = NET_API_STATS_REPORT_INTERVAL;

#if (DEBUG || DEVELOPMENT)
SYSCTL_UINT(_net_stats, OID_AUTO, api_report_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &net_api_stats_report_interval, 0, "");
#endif /* DEBUG || DEVELOPMENT */

static os_log_t nstat_log_handle = NULL;
#define _NSTAT_LOG(handle, type, fmt, ...) do {                           \
	os_log_with_type(handle, type, "%s - " fmt, __func__, ##__VA_ARGS__); \
} while (0)

#define NSTAT_LOG(fmt, ...)         _NSTAT_LOG(nstat_log_handle, OS_LOG_TYPE_DEFAULT, fmt, ##__VA_ARGS__)
#define NSTAT_LOG_DEBUG(fmt, ...)   _NSTAT_LOG(nstat_log_handle, OS_LOG_TYPE_DEBUG,   fmt, ##__VA_ARGS__)
#define NSTAT_LOG_INFO(fmt, ...)    _NSTAT_LOG(nstat_log_handle, OS_LOG_TYPE_INFO,    fmt, ##__VA_ARGS__)
#define NSTAT_LOG_ERROR(fmt, ...)   _NSTAT_LOG(nstat_log_handle, OS_LOG_TYPE_ERROR,   fmt, ##__VA_ARGS__)

#define NSTAT_DEBUG_SOCKET_PID_MATCHED(so) \
    (so && (nstat_debug_pid == (so->so_flags & SOF_DELEGATED ? so->e_pid : so->last_pid)))

#define NSTAT_DEBUG_SOCKET_ON(so) \
    ((nstat_debug && (!nstat_debug_pid || NSTAT_DEBUG_SOCKET_PID_MATCHED(so))) ? nstat_debug : 0)

#define NSTAT_DEBUG_SOCKET_LOG(so, fmt, ...)        \
    if (NSTAT_DEBUG_SOCKET_ON(so)) {                \
	    NSTAT_LOG_DEBUG("NSTAT_DEBUG_SOCKET <pid %d>: " fmt, (so->so_flags & SOF_DELEGATED ? so->e_pid : so->last_pid), ##__VA_ARGS__); \
    }

enum{
	NSTAT_FLAG_CLEANUP              = (1 << 0),
	NSTAT_FLAG_REQCOUNTS            = (1 << 1),
	NSTAT_FLAG_SUPPORTS_UPDATES     = (1 << 2),
	NSTAT_FLAG_SYSINFO_SUBSCRIBED   = (1 << 3),
};

static int
progress_indicators SYSCTL_HANDLER_ARGS
{
	return ntstat_progress_indicators(req);
}

SYSCTL_PROC(_net_stats, OID_AUTO, progress,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY, 0, 0,
    progress_indicators, "S", "Various items that indicate the current state of progress on the link");

#if !XNU_TARGET_OS_OSX
#define QUERY_CONTINUATION_SRC_COUNT 50
#else /* XNU_TARGET_OS_OSX */
#define QUERY_CONTINUATION_SRC_COUNT 100
#endif /* XNU_TARGET_OS_OSX */
#define QUERY_CONTINUATION_MIN_SRC_COUNT 5

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


typedef void *nstat_provider_cookie_t;

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


struct nstat_global_counts {
	uint64_t nstat_global_client_current;   // current number of clients overall
	uint64_t nstat_global_client_max;       // max number of clients overall
	uint64_t nstat_global_client_allocs;    // total number of clients allocated

	uint64_t nstat_global_src_current;      // current number of srcs overall
	uint64_t nstat_global_src_max;          // max number of srcs overall
	uint64_t nstat_global_src_allocs;       // total number of sources allocated
	uint64_t nstat_global_src_idlecheck_gone;// total number of sources discovered "gone" in idle check

	uint64_t nstat_global_tucookie_current; // current number of tucookies overall
	uint64_t nstat_global_tucookie_max;     // max number of tucookies overall
	uint64_t nstat_global_tucookie_allocs;  // total number of tucookies allocated
	// Details for tucookie lifecycle
	uint64_t nstat_global_tucookie_skip_dead; // When adding a watcher, pcb with "dead" state skipped over
	uint64_t nstat_global_tucookie_skip_stopusing; // When adding a watcher, pcb marked as stop using
	uint64_t nstat_global_tucookie_alloc_fail;     // Allocation failure for a tucookie

	uint64_t nstat_global_tu_shad_current;  // current number of nstat_tu_shadow objects overall
	uint64_t nstat_global_tu_shad_max;      // max number of tu_shadows overall
	uint64_t nstat_global_tu_shad_allocs;   // total number of tu_shadows allocated

	uint64_t nstat_global_gshad_current;    // current number of generic shadow objects overall
	uint64_t nstat_global_gshad_max;        // max number of srcs overall
	uint64_t nstat_global_gshad_allocs;     // total number of sources allocated

	uint64_t nstat_global_procdetails_current;// current number of procdetails objects overall
	uint64_t nstat_global_procdetails_max;   // max number of procdetails overall
	uint64_t nstat_global_procdetails_allocs;// total number of procdetails allocated
};

struct nstat_metrics {
	uint32_t nstat_src_current;             // current number of srcs for client
	uint32_t nstat_src_max;                 // max number of srcs for client
	uint32_t nstat_first_uint32_count;      // Subsequent fields must be uint32_t values that, if kept per-client,
	                                        // should simply added to the global counts when the client exit

	// Tracking client requests
	uint32_t nstat_query_request_all;       // Client requests for all counts
	uint32_t nstat_query_request_one;       // Client request for counts on a single source
	uint32_t nstat_query_description_all;   // Client requests for all descriptors
	uint32_t nstat_query_description_one;   // Client requests for descriptor on a single source
	uint32_t nstat_query_update_all;        // Client requests for all updates
	uint32_t nstat_query_update_one;        // Client requests for update on a single source
	uint32_t nstat_remove_src_found;        // Client request to remove a source which is still in existence
	uint32_t nstat_remove_src_missed;       // Client request to remove a source which is no longer there

	// Details for nstat_query_request all/one
	uint32_t nstat_query_request_nobuf;     // No buffers for message send
	uint32_t nstat_query_request_upgrade;   // Successful lock upgrade to handle "gone" source
	uint32_t nstat_query_request_noupgrade; // Unsuccessful lock upgrade to handle "gone" source
	uint32_t nstat_query_request_nodesc;    // Can't send a descriptor for "gone" source
	uint32_t nstat_query_request_yield;     // Client yields lock due to possibly higher priority processing
	uint32_t nstat_query_request_limit;     // Client requests for all counts

	// Details for nstat_query_description all/one
	uint32_t nstat_query_description_nobuf; // No buffers for message send
	uint32_t nstat_query_description_yield; // Client yields lock due to possibly higher priority processing
	uint32_t nstat_query_description_limit; // Client requests for all counts

	// Details for nstat_query_update all/one
	uint32_t nstat_query_update_nobuf;      // No buffers for message send
	uint32_t nstat_query_update_upgrade;    // Successful lock upgrade to handle "gone" source
	uint32_t nstat_query_update_noupgrade;  // Unsuccessful lock upgrade to handle "gone" source
	uint32_t nstat_query_update_nodesc;     // Can't send a descriptor for "gone" source
	uint32_t nstat_query_update_yield;      // Client yields lock due to possibly higher priority processing
	uint32_t nstat_query_update_limit;      // Client requests for all counts

	// Details for adding a source
	uint32_t nstat_src_add_success;         // successful src_add
	uint32_t nstat_src_add_no_buf;          // fail to get buffer for initial src-added
	uint32_t nstat_src_add_no_src_mem;      // fail to get memory for nstat_src structure
	uint32_t nstat_src_add_send_err;        // fail to send initial src-added
	uint32_t nstat_src_add_while_cleanup;   // fail to add because client is in clean up state

	uint32_t nstat_src_gone_idlecheck;      // src gone noted during periodic idle check

	uint32_t nstat_last_uint32_count;       // Must be the last uint32_t count in the structure
	uint32_t nstat_stats_pad;
};

#define NUM_NSTAT_METRICS_UINT32_COUNTS ((__builtin_offsetof(struct nstat_metrics, nstat_last_uint32_count) - \
	                                  __builtin_offsetof(struct nstat_metrics, nstat_first_uint32_count)) / sizeof(uint32_t))


typedef struct nstat_trace_entry {
	u_int32_t                       nte_seqno;
	u_int32_t                       nte_event;
	u_int64_t                       nte_qualifier;
} nstat_trace_entry;

#define NSTAT_TRACE_ENTRIES_PER_CLIENT  (16 * 1024)

typedef struct nstat_cyclic_trace {
	uint32_t            ntt_next_trace_id;
	int32_t             ntt_pad;
	nstat_trace_entry   ntt_entry[NSTAT_TRACE_ENTRIES_PER_CLIENT];
} nstat_cyclic_trace;


typedef struct nstat_client {
	struct nstat_client      *ntc_next;
	/* A bitmask to indicate whether a provider ever done NSTAT_MSG_TYPE_ADD_ALL_SRCS */
	u_int32_t               ntc_watching;
	/* A bitmask to indicate whether a provider ever done NSTAT_MSG_TYPE_ADD_SRC */
	u_int32_t               ntc_added_src;
	decl_lck_mtx_data(, ntc_user_mtx);      // Mutual exclusion for user level requests on this ntc_client
	kern_ctl_ref            ntc_kctl;
	u_int32_t               ntc_unit;
	nstat_src_ref_t         ntc_next_srcref;
	tailq_head_nstat_src    ntc_src_queue;
	mbuf_t                  ntc_accumulated;
	u_int32_t               ntc_flags;
	nstat_provider_filter   ntc_provider_filters[NSTAT_PROVIDER_COUNT];
	/* state maintained for partial query requests */
	u_int64_t               ntc_context;
	u_int64_t               ntc_seq;
	/* For ease of debugging with lldb macros */
	struct nstat_procdetails *ntc_procdetails;
	struct nstat_metrics    ntc_metrics;
#if NSTAT_TRACE_ENABLED
	nstat_cyclic_trace      *ntc_trace;
#endif
} nstat_client;

typedef struct nstat_provider {
	struct nstat_provider   *next;
	nstat_provider_id_t     nstat_provider_id;
	size_t                  nstat_descriptor_length;
	errno_t                 (*nstat_lookup)(const void *__sized_by (length)data, u_int32_t length, nstat_provider_cookie_t *out_cookie);
	int                     (*nstat_gone)(nstat_provider_cookie_t cookie);
	errno_t                 (*nstat_counts)(nstat_provider_cookie_t cookie, struct nstat_counts *out_counts, int *out_gone);
	errno_t                 (*nstat_watcher_add)(nstat_client *client, nstat_msg_add_all_srcs *req);
	void                    (*nstat_watcher_remove)(nstat_client *client);
	errno_t                 (*nstat_copy_descriptor)(nstat_provider_cookie_t cookie, void *__sized_by (len)data, size_t len);
	void                    (*nstat_release)(nstat_provider_cookie_t cookie, boolean_t locked);
	bool                    (*nstat_reporting_allowed)(nstat_provider_cookie_t cookie, nstat_provider_filter *filter, u_int64_t suppression_flags);
	bool                    (*nstat_cookie_equal)(nstat_provider_cookie_t cookie1, nstat_provider_cookie_t cookie2);
	size_t                  (*nstat_copy_extension)(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *buf, size_t len);
} nstat_provider;

typedef struct nstat_src {
	tailq_entry_nstat_src   nts_client_link;    // All sources for the nstat_client, for iterating over.
	nstat_client            *nts_client;        // The nstat_client that this is a source for
	nstat_src_ref_t         nts_srcref;         // The reference quoted in any messages
	nstat_provider          *nts_provider;      // The "provider" for the source, e.g. for kernel TCP sockets
	nstat_provider_cookie_t nts_cookie;         // Provider-specific futher information,
	uint32_t                nts_filter;
	bool                    nts_reported;       // At least one update/counts/desc message has been sent
	uint64_t                nts_seq;            // Keeping track when getting partial poll results
} nstat_src;

// The merge structures are intended to give a global picture of what may be asked for by the current set of clients
// This is to avoid taking locks to check them all individually
typedef struct nstat_merged_provider_filter {
	u_int64_t               mf_events;      // So far we only merge the events portion of any filters
} nstat_merged_provider_filter;

typedef struct nstat_merged_provider_filters {
	nstat_merged_provider_filter    mpf_filters[NSTAT_PROVIDER_COUNT];
} nstat_merged_provider_filters;

static errno_t      nstat_client_send_counts(nstat_client *client, nstat_src *src, unsigned long long context, u_int16_t hdr_flags, int *gone);
static int          nstat_client_send_description(nstat_client *client, nstat_src *src, u_int64_t context, u_int16_t hdr_flags);
static int          nstat_client_send_update(nstat_client *client, nstat_src *src, u_int64_t context, u_int64_t event, u_int16_t hdr_flags, int *gone);
static errno_t      nstat_client_send_removed(nstat_client *client, nstat_src *src, u_int16_t hdr_flags);
static errno_t      nstat_client_send_goodbye(nstat_client  *client, nstat_src *src);
static void         nstat_client_cleanup_source(nstat_client *client, nstat_src *src, boolean_t);
static bool         nstat_client_reporting_allowed(nstat_client *client, nstat_src *src, u_int64_t suppression_flags);
static boolean_t    nstat_client_begin_query(nstat_client *client, const nstat_msg_hdr *hdrp);
static u_int16_t    nstat_client_end_query(nstat_client *client, nstat_src *last_src, boolean_t partial);
static void         nstat_ifnet_report_lim_stats(void);
static void         nstat_net_api_report_stats(void);
static errno_t      nstat_set_provider_filter( nstat_client  *client, nstat_msg_add_all_srcs *req);
static errno_t      nstat_client_send_event(nstat_client *client, nstat_src *src, u_int64_t event);

static u_int32_t    nstat_udp_watchers = 0;
static u_int32_t    nstat_tcp_watchers = 0;
static nstat_merged_provider_filters merged_filters = {};

static nstat_client *nstat_clients = NULL;
static uint64_t     nstat_idle_time = 0;

#if NSTAT_FUZZ_TIMING
static uint32_t nstat_random_delay_insert_modulo = 5000;
static uint32_t nstat_max_nsec_delay = (NSEC_PER_SEC / 1000);
#endif // NSTAT_FUZZ_TIMING

static struct nstat_metrics nstat_metrics;
static struct nstat_global_counts nstat_global_counts;

// For lldb macro usage
static __unused const size_t nstat_trace_entries_per_client = NSTAT_TRACE_ENTRIES_PER_CLIENT;

#if NSTAT_TRACE_ENABLED
static nstat_cyclic_trace      nstat_global_trace;
#endif

#if NSTAT_TRACE_ENABLED
#define NSTAT_TRACE(field, client, qual) \
{ \
    nstat_trace(offsetof(struct nstat_metrics, field), client, (uint64_t)qual); \
}
#else // NSTAT_TRACE_ENABLED
#define NSTAT_TRACE(field, client, qual)
#endif

#if NSTAT_FUZZ_TIMING
#define NSTAT_RANDOM_DELAY(client) \
{ \
    nstat_random_delay(client); \
}
#else
#define NSTAT_RANDOM_DELAY(client)
#endif

#define NSTAT_NOTE_QUAL(field, client, qual) \
{   \
    NSTAT_TRACE(field, client, qual); \
    NSTAT_RANDOM_DELAY(client); \
    client->ntc_metrics.field++; \
}

#define NSTAT_NOTE_SRC(field, client, src) \
{   \
    NSTAT_TRACE(field, client, (src != NULL)? src->nts_srcref: 0); \
    NSTAT_RANDOM_DELAY(client); \
    client->ntc_metrics.field++; \
}

#define NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(_currentfield, _maxfield) \
{   \
	uint64_t _prev_count = os_atomic_inc_orig(&nstat_global_counts._currentfield, relaxed); \
	if (_prev_count >= os_atomic_load(&nstat_global_counts._maxfield, relaxed)) {  \
	        os_atomic_store(&nstat_global_counts._maxfield, _prev_count + 1, relaxed); \
	}   \
}

#define NSTAT_GLOBAL_COUNT_INCREMENT(_field) \
{   \
	os_atomic_inc_orig(&nstat_global_counts._field, relaxed); \
}

#define NSTAT_GLOBAL_COUNT_DECREMENT(_field) \
{   \
	os_atomic_dec_orig(&nstat_global_counts._field, relaxed); \
}

static errno_t      nstat_client_send_counts(nstat_client *client, nstat_src *src, unsigned long long context, u_int16_t hdr_flags, int *gone);
static int          nstat_client_send_description(nstat_client *client, nstat_src *src, u_int64_t context, u_int16_t hdr_flags);
static int          nstat_client_send_update(nstat_client *client, nstat_src *src, u_int64_t context, u_int64_t event, u_int16_t hdr_flags, int *gone);
static errno_t      nstat_client_send_removed(nstat_client *client, nstat_src *src, u_int16_t hdr_flags);
static errno_t      nstat_client_send_goodbye(nstat_client  *client, nstat_src *src);
static void         nstat_client_cleanup_source(nstat_client *client, nstat_src *src, boolean_t);
static bool         nstat_client_reporting_allowed(nstat_client *client, nstat_src *src, u_int64_t suppression_flags);
static boolean_t    nstat_client_begin_query(nstat_client *client, const nstat_msg_hdr *hdrp);
static u_int16_t    nstat_client_end_query(nstat_client *client, nstat_src *last_src, boolean_t partial);
static void         nstat_ifnet_report_lim_stats(void);
static void         nstat_net_api_report_stats(void);
static errno_t      nstat_set_provider_filter( nstat_client  *client, nstat_msg_add_all_srcs *req);
static errno_t      nstat_client_send_event(nstat_client *client, nstat_src *src, u_int64_t event);
static void         nstat_client_register(void);

/*
 * The lock order is as follows:
 *
 *     nstat_rwlock
 *
 * Or:
 *
 * client->ntc_user_mtx
 *     nstat_rwlock
 *
 *
 * The nstat_rwlock may be held in exclusive (writer) or shared (reader) mode.
 *
 * In general, events from the kernel, such as flow creation and deletion,
 * require that the lock be held in exclusive mode while "nstat_src" structures
 * are created or destroyed and appropriate linkages made or broken.
 *
 * In contrast, things that are driven from ntstat user level clients,
 * most obviously polls, typically only require shared mode locking.
 * There are some rare exceptions where a need to manipulate linkages
 * that go across multiple clients will require an upgrade to an exlusive lock.
 *
 * There is one other lock to consider. Calls from NetworkStatistics clients will first
 * obtain the per-client ntc_user_mtx.  This ensures that only one such client thread
 * can be in progress at a time, making it easier to reason about correctness.
 */
static LCK_ATTR_DECLARE(nstat_lck_attr, 0, 0);
static LCK_GRP_DECLARE(nstat_lck_grp, "network statistics kctl");
static LCK_RW_DECLARE_ATTR(nstat_rwlock, &nstat_lck_grp, &nstat_lck_attr);

#define NSTAT_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&nstat_rwlock)
#define NSTAT_LOCK_SHARED() lck_rw_lock_shared(&nstat_rwlock)
#define NSTAT_LOCK_SHARED_TO_EXCLUSIVE() lck_rw_lock_shared_to_exclusive(&nstat_rwlock)
#define NSTAT_LOCK_EXCLUSIVE_TO_SHARED() lck_rw_lock_exclusive_to_shared(&nstat_rwlock)
#define NSTAT_UNLOCK() lck_rw_done(&nstat_rwlock)
#define NSTAT_UNLOCK_EXCLUSIVE() lck_rw_unlock_exclusive(&nstat_rwlock)
#define NSTAT_UNLOCK_SHARED() lck_rw_unlock_shared(&nstat_rwlock)
#define NSTAT_LOCK_WOULD_YIELD() lck_rw_lock_would_yield_shared(&nstat_rwlock)
#define NSTAT_LOCK_YIELD() lck_rw_lock_yield_shared(&nstat_rwlock, FALSE)
#define NSTAT_ASSERT_LOCKED_EXCLUSIVE() LCK_RW_ASSERT(&nstat_rwlock, LCK_RW_ASSERT_EXCLUSIVE)
#define NSTAT_ASSERT_LOCKED_SHARED() LCK_RW_ASSERT(&nstat_rwlock, LCK_RW_ASSERT_SHARED)
#define NSTAT_ASSERT_LOCKED() LCK_RW_ASSERT(&nstat_rwlock, LCK_RW_ASSERT_HELD)
#define NSTAT_ASSERT_UNLOCKED() LCK_RW_ASSERT(&nstat_rwlock, LCK_RW_ASSERT_NOTHELD)

typedef enum {
	NSTAT_LOCK_NOTHELD  = 0,
	NSTAT_LOCK_HELD     = 1,
} nstat_lock_status;

/* some extern definitions */
extern void tcp_report_stats(void);

#if NSTAT_TRACE_ENABLED
static void
nstat_trace(int32_t trace_id, nstat_client *client, uint64_t qual)
{
	nstat_cyclic_trace *trace;
	nstat_trace_entry *entry;
	uint32_t seqno;
	if (client == NULL) {
		trace = &nstat_global_trace;
	} else {
		trace = client->ntc_trace;
	}
	if (trace != NULL) {
		seqno = OSIncrementAtomic(&trace->ntt_next_trace_id);
		if (seqno > (NSTAT_TRACE_ENTRIES_PER_CLIENT - 2)) {
			seqno = NSTAT_TRACE_ENTRIES_PER_CLIENT - 2;
		}
		int32_t index = seqno % NSTAT_TRACE_ENTRIES_PER_CLIENT;
		entry = &trace->ntt_entry[index];
		entry->nte_seqno = seqno;
		entry->nte_event = trace_id;
		entry->nte_qualifier = qual;
	}
}
#endif

#if NSTAT_FUZZ_TIMING
static void
nstat_random_delay(nstat_client *client)
{
	if (nstat_random_delay_insert_modulo) {
		uint64_t random;
		read_random(&random, sizeof(random));
		if ((random % nstat_random_delay_insert_modulo) == 0) {
#if NSTAT_TRACE_ENABLED
			nstat_trace(1, client, 0);
#endif
			read_random(&random, sizeof(random));
			uint64_t nsec_delay = (random % nstat_max_nsec_delay);
			delay_for_interval(nsec_delay, 1);
#if NSTAT_TRACE_ENABLED
			nstat_trace(2, client, 0);
#endif
		}
	}
}
#endif

static void
nstat_accumulate_client_metrics(nstat_client *client)
{
	if (nstat_metrics.nstat_src_max < client->ntc_metrics.nstat_src_max) {
		nstat_metrics.nstat_src_max = client->ntc_metrics.nstat_src_max;
	}
	// Most of the counts happen to be consecutive uint32_t values that can be picked up via pointer iteration rather than name
	uint32_t *srcptr = __unsafe_forge_bidi_indexable(uint32_t *,
	    (uint32_t *)(void *)&client->ntc_metrics.nstat_first_uint32_count,
	    (NUM_NSTAT_METRICS_UINT32_COUNTS * sizeof(uint32_t)));
	uint32_t *destptr = __unsafe_forge_bidi_indexable(uint32_t *,
	    (uint32_t *)(void *)&nstat_metrics.nstat_first_uint32_count,
	    (NUM_NSTAT_METRICS_UINT32_COUNTS * sizeof(uint32_t)));

	for (int i = 0; i < NUM_NSTAT_METRICS_UINT32_COUNTS; i++) {
		destptr[i] += srcptr[i];
	}
}

static void
nstat_copy_sa_out(
	const struct sockaddr   *src,
	struct sockaddr                 *dst,
	int                                             maxlen)
{
	if (src->sa_len > maxlen) {
		return;
	}

	SOCKADDR_COPY(src, dst, src->sa_len);
	if (src->sa_family == AF_INET6 &&
	    src->sa_len >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6     *sin6 = SIN6(dst);
		if (IN6_IS_SCOPE_EMBED(&sin6->sin6_addr)) {
			sin6->sin6_scope_id = (SIN6(src))->sin6_scope_id;
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

u_int32_t
nstat_ifnet_to_flags(
	struct ifnet *ifp)
{
	u_int32_t flags = 0;
	u_int32_t functional_type = if_functional_type(ifp, FALSE);
	u_int32_t peer_egress_functional_type = IFRTYPE_FUNCTIONAL_UNKNOWN;

	// If known VPN, check the delegate interface to see if it has peer
	// egress interface type set to cell.
	peer_egress_functional_type = if_peer_egress_functional_type(ifp, !(IFNET_IS_VPN(ifp)));

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
		flags |= NSTAT_IFNET_IS_WIFI | NSTAT_IFNET_IS_WIFI_INFRA;
		break;
	case IFRTYPE_FUNCTIONAL_WIFI_AWDL:
		flags |= NSTAT_IFNET_IS_WIFI | NSTAT_IFNET_IS_AWDL;
		break;
	case IFRTYPE_FUNCTIONAL_CELLULAR:
		flags |= NSTAT_IFNET_IS_CELLULAR;
		break;
	case IFRTYPE_FUNCTIONAL_COMPANIONLINK:
		flags |= NSTAT_IFNET_IS_COMPANIONLINK;
		if (IFNET_IS_COMPANION_LINK_BLUETOOTH(ifp)) {
			flags |= NSTAT_IFNET_IS_COMPANIONLINK_BT;
		}
		break;
	}

	switch (peer_egress_functional_type) {
	case IFRTYPE_FUNCTIONAL_CELLULAR:
		flags |= NSTAT_IFNET_PEEREGRESSINTERFACE_IS_CELLULAR;
		break;
	}

	if (IFNET_IS_EXPENSIVE(ifp)) {
		flags |= NSTAT_IFNET_IS_EXPENSIVE;
	}
	if (IFNET_IS_CONSTRAINED(ifp)) {
		flags |= NSTAT_IFNET_IS_CONSTRAINED;
	}
	if (ifnet_is_low_latency(ifp)) {
		flags |= NSTAT_IFNET_IS_WIFI | NSTAT_IFNET_IS_LLW;
	}
	if (IFNET_IS_VPN(ifp)) {
		flags |= NSTAT_IFNET_IS_VPN;
	}

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
			flags = nstat_ifnet_to_flags(ifp);

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
	// The nstat_rwlock is assumed locked
	NSTAT_ASSERT_LOCKED();

	nstat_merged_provider_filters new_merge = {};
	nstat_provider_type_t provider;
	nstat_client *client;

	for (client = nstat_clients; client; client = client->ntc_next) {
		for (provider = NSTAT_PROVIDER_NONE; provider <= NSTAT_PROVIDER_LAST; provider++) {
			new_merge.mpf_filters[provider].mf_events |= client->ntc_provider_filters[provider].npf_events;
		}
	}
	for (provider = NSTAT_PROVIDER_NONE; provider <= NSTAT_PROVIDER_LAST; provider++) {
		// This should do atomic updates of the 64 bit words, where memcpy would be undefined
		merged_filters.mpf_filters[provider].mf_events = new_merge.mpf_filters[provider].mf_events;
	}
}


#pragma mark -- Network Statistic Providers --

static errno_t nstat_client_source_add(u_int64_t context, nstat_client *client, nstat_provider *provider,
    nstat_provider_cookie_t cookie, nstat_lock_status lock_status);
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
	const void              *__sized_by(length)data,
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
nstat_client_sanitize_cookie(
	nstat_client            *client,
	nstat_provider_id_t     id,
	nstat_provider_cookie_t cookie)
{
	nstat_src *src = NULL;

	// Scan the source list to find any duplicate entry and remove it.
	NSTAT_LOCK_EXCLUSIVE();
	TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
	{
		nstat_provider *sp = src->nts_provider;
		if (sp->nstat_provider_id == id &&
		    sp->nstat_cookie_equal != NULL &&
		    sp->nstat_cookie_equal(src->nts_cookie, cookie)) {
			break;
		}
	}
	if (src) {
		nstat_client_send_goodbye(client, src);
		TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	if (src) {
		nstat_client_cleanup_source(NULL, src, TRUE);
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
	nstat_log_handle = os_log_create("com.apple.xnu.net", "ntstat");
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
	nstat_client_register();
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

	NSTAT_LOCK_SHARED();
	TAILQ_FOREACH(procdetails, &nstat_procdetails_head, pdet_link) {
		assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);

		if (procdetails->pdet_upid == upid) {
			OSIncrementAtomic(&procdetails->pdet_refcnt);
			break;
		}
	}
	NSTAT_UNLOCK_SHARED();

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
		NSTAT_LOCK_EXCLUSIVE();
		TAILQ_INSERT_HEAD(&nstat_procdetails_head, procdetails, pdet_link);
		NSTAT_UNLOCK_EXCLUSIVE();
		NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_procdetails_allocs);
		NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(nstat_global_procdetails_current, nstat_global_procdetails_max);
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
	NSTAT_LOCK_EXCLUSIVE();

	TAILQ_FOREACH_SAFE(procdetails, &nstat_procdetails_head, pdet_link, tmpdetails)
	{
		assert(procdetails->pdet_magic == NSTAT_PROCDETAILS_MAGIC);
		if (procdetails->pdet_refcnt == 0) {
			// Pull it off the list
			TAILQ_REMOVE(&nstat_procdetails_head, procdetails, pdet_link);
			TAILQ_INSERT_TAIL(&dead_list, procdetails, pdet_link);
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	while ((procdetails = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, procdetails, pdet_link);
		procdetails->pdet_magic = NSTAT_PROCDETAILS_UNMAGIC;
		NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_procdetails_current);
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
	struct sockaddr                 *dst = NULL;
	struct sockaddr                 *mask = NULL;
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

	dst = __DECONST_SA(&param->dst.v4);
	mask = param->mask.v4.sin_family ? __DECONST_SA(&param->mask.v4) : NULL;

	struct radix_node_head  *rnh = rt_tables[dst->sa_family];
	if (rnh == NULL) {
		return EAFNOSUPPORT;
	}

	lck_mtx_lock(rnh_lock);
	struct rtentry *rt = rt_lookup(TRUE, dst, mask, rnh, param->ifindex);
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
	nstat_client     *client  = (nstat_client*)context;

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

		result = nstat_client_source_add(0, client, &nstat_route_provider, rt, NSTAT_LOCK_NOTHELD);
		if (result != 0) {
			rtfree_locked(rt);
		}
	}

	return result;
}

static errno_t
nstat_route_add_watcher(
	nstat_client *client,
	nstat_msg_add_all_srcs *req)
{
	int i;
	errno_t result = 0;

	lck_mtx_lock(rnh_lock);

	result = nstat_set_provider_filter(client, req);
	if (result == 0) {
		OSIncrementAtomic(&nstat_route_watchers);

		for (i = 1; i < AF_MAX; i++) {
			struct radix_node_head *rnh;
			rnh = rt_tables[i];
			if (!rnh) {
				continue;
			}

			result = rnh->rnh_walktree(rnh, nstat_route_walktree_add, client);
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

	NSTAT_LOCK_EXCLUSIVE();
	if ((rt->rt_flags & RTF_UP) != 0) {
		nstat_client *client;
		for (client = nstat_clients; client; client = client->ntc_next) {
			if ((client->ntc_watching & (1 << NSTAT_PROVIDER_ROUTE)) != 0) {
				// this client is watching routes
				// acquire a reference for the route
				RT_ADDREF(rt);

				// add the source, if that fails, release the reference
				if (nstat_client_source_add(0, client, &nstat_route_provider, rt, NSTAT_LOCK_HELD) != 0) {
					RT_REMREF(rt);
				}
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
}

static void
nstat_route_remove_watcher(
	__unused nstat_client    *client)
{
	OSDecrementAtomic(&nstat_route_watchers);
}

static errno_t
nstat_route_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *__sized_by(len)data,
	size_t                  len)
{
	nstat_route_descriptor  *desc = (nstat_route_descriptor*)data;
	if (len < sizeof(*desc)) {
		return EINVAL;
	}
	bzero(desc, sizeof(*desc));

	struct rtentry  *rt = (struct rtentry*)cookie;
	desc->id = (uint64_t)VM_KERNEL_ADDRHASH(rt);
	desc->parent_id = (uint64_t)VM_KERNEL_ADDRHASH(rt->rt_parent);
	desc->gateway_id = (uint64_t)VM_KERNEL_ADDRHASH(rt->rt_gwroute);


	// key/dest
	struct sockaddr *sa;
	if ((sa = rt_key(rt))) {
		nstat_copy_sa_out(sa, &desc->dst.sa, sizeof(desc->dst));
	}

	// mask
	if ((sa = rt_mask(rt))) {
		nstat_copy_sa_out(sa, &desc->mask.sa, sizeof(desc->mask));
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
			uint32_t interface_properties = nstat_ifnet_to_flags(ifp);

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
	struct nstat_counts * __single  result = rte->rt_stats;
	if (result) {
		return result;
	}

	result = kalloc_type(struct nstat_counts, Z_WAITOK | Z_ZERO);
	if (!result) {
		return result;
	}

	if (!OSCompareAndSwapPtr(NULL, result, &rte->rt_stats)) {
		kfree_type(struct nstat_counts, result);
		result = rte->rt_stats;
	}

	return result;
}

__private_extern__ void
nstat_route_detach(
	struct rtentry  *rte)
{
	if (rte->rt_stats) {
		kfree_type(struct nstat_counts, rte->rt_stats);
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

#define PNAME_MAX_LENGTH    ((2 * MAXCOMLEN) + 1)

/*
 * Due to the way the kernel deallocates a process (the process structure
 * might be gone by the time we get the PCB detach notification),
 * we need to cache the process name. Without this, proc_best_name_for_pid()
 * would return null and the process name would never be sent to userland.
 *
 * For UDP sockets, we also store the cached the connection tuples along with
 * the interface index. This is necessary because when UDP sockets are
 * disconnected, the connection tuples are forever lost from the inpcb, thus
 * we need to keep track of the last call to connect() in ntstat.
 */
struct nstat_tucookie {
	struct inpcb    *inp;
	char            pname[PNAME_MAX_LENGTH];
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
nstat_tucookie_alloc_ref_internal(
	struct inpcb *inp,
	bool          locked)
{
	struct nstat_tucookie *cookie;

	if (inp->inp_state == INPCB_STATE_DEAD) {
		NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_tucookie_skip_dead);
		return NULL;
	}

	cookie = kalloc_type(struct nstat_tucookie, Z_WAITOK | Z_ZERO);

	if (cookie == NULL) {
		NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_tucookie_alloc_fail);
		return NULL;
	}
	NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_tucookie_allocs);
	NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(nstat_global_tucookie_current, nstat_global_tucookie_max);

	if (in_pcb_checkstate(inp, WNT_ACQUIRE, locked) == WNT_STOPUSING) {
		NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_tucookie_skip_stopusing);
		NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_tucookie_current);
		kfree_type(struct nstat_tucookie, cookie);
		return NULL;
	}
	cookie->inp = inp;
	proc_best_name_for_pid(inp->inp_socket->last_pid, cookie->pname, sizeof(cookie->pname));
	/*
	 * We only increment the reference count for UDP sockets because we
	 * only cache UDP socket tuples.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP) {
		OSIncrementAtomic(&inp->inp_nstat_refcnt);
	}

	return cookie;
}

static struct nstat_tucookie *
nstat_tucookie_alloc_ref(
	struct inpcb *inp)
{
	return nstat_tucookie_alloc_ref_internal(inp, false);
}

static struct nstat_tucookie *
nstat_tucookie_alloc_ref_locked(
	struct inpcb *inp)
{
	return nstat_tucookie_alloc_ref_internal(inp, true);
}

static void
nstat_tucookie_release_internal(
	struct nstat_tucookie *cookie,
	int                   inplock)
{
	if (SOCK_PROTO(cookie->inp->inp_socket) == IPPROTO_UDP) {
		OSDecrementAtomic(&cookie->inp->inp_nstat_refcnt);
	}
	in_pcb_checkstate(cookie->inp, WNT_RELEASE, inplock);
	NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_tucookie_current);
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

static size_t
nstat_inp_bluetooth_counts(struct inpcb *inp, nstat_interface_counts *buf, size_t len)
{
	// Note, the caller has guaranteed that the buffer has been zeroed, there is no need to clear it again
	struct socket *so = inp->inp_socket;

	if (so == NULL) {
		return 0;
	}

	if (buf == NULL) {
		uint64_t rxbytes = 0;
		uint64_t txbytes = 0;
		rxbytes = os_atomic_load(&inp->inp_btstat->rxbytes, relaxed);
		txbytes = os_atomic_load(&inp->inp_btstat->txbytes, relaxed);

		if ((rxbytes == 0) && (txbytes == 0)) {
			// It's more efficient to skip sending counts if they're only going to be zero
			return 0;
		}
		return sizeof(nstat_interface_counts);
	}

	if (len < sizeof(nstat_interface_counts)) {
		return 0;
	}

	// if the pcb is in the dead state, we should stop using it
	if (!(intotcpcb(inp)) || inp->inp_state == INPCB_STATE_DEAD) {
		return 0;
	}
	buf->nstat_rxpackets = os_atomic_load(&inp->inp_btstat->rxpackets, relaxed);
	buf->nstat_rxbytes = os_atomic_load(&inp->inp_btstat->rxbytes, relaxed);
	buf->nstat_txpackets = os_atomic_load(&inp->inp_btstat->txpackets, relaxed);
	buf->nstat_txbytes = os_atomic_load(&inp->inp_btstat->txbytes, relaxed);
	return sizeof(nstat_interface_counts);
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
	nstat_client            *client,
	nstat_msg_add_all_srcs  *req)
{
	// There is a tricky issue around getting all TCP sockets added once
	// and only once.  nstat_tcp_new_pcb() is called prior to the new item
	// being placed on any lists where it might be found.
	// By locking the tcbinfo.ipi_lock prior to marking the client as a watcher,
	// it should be impossible for a new socket to be added twice.
	// On the other hand, there is still a timing issue where a new socket
	// results in a call to nstat_tcp_new_pcb() before this watcher
	// is instantiated and yet the socket doesn't make it into ipi_listhead
	// prior to the scan.  <rdar://problem/30361716>

	errno_t result;

	lck_rw_lock_shared(&tcbinfo.ipi_lock);
	result = nstat_set_provider_filter(client, req);
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
			if (nstat_client_source_add(0, client, &nstat_tcp_provider,
			    cookie, NSTAT_LOCK_NOTHELD) != 0) {
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
	__unused nstat_client    *client)
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
	NSTAT_LOCK_EXCLUSIVE();
	nstat_client     *client;
	for (client = nstat_clients; client; client = client->ntc_next) {
		if ((client->ntc_watching & (1 << NSTAT_PROVIDER_TCP_KERNEL)) != 0) {
			// this client is watching tcp
			// acquire a reference for it
			cookie = nstat_tucookie_alloc_ref_locked(inp);
			if (cookie == NULL) {
				continue;
			}
			// add the source, if that fails, release the reference
			if (nstat_client_source_add(0, client,
			    &nstat_tcp_provider, cookie, NSTAT_LOCK_HELD) != 0) {
				nstat_tucookie_release_locked(cookie);
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
	socket_unlock(inp->inp_socket, 0);
}

__private_extern__ void
nstat_pcb_detach(struct inpcb *inp)
{
	nstat_client *client;
	nstat_src *src;
	tailq_head_nstat_src dead_list;
	struct nstat_tucookie *tucookie;
	errno_t result;

	if (inp == NULL || (nstat_tcp_watchers == 0 && nstat_udp_watchers == 0)) {
		return;
	}

	TAILQ_INIT(&dead_list);
	NSTAT_LOCK_EXCLUSIVE();
	for (client = nstat_clients; client; client = client->ntc_next) {
		TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
		{
			nstat_provider_id_t provider_id = src->nts_provider->nstat_provider_id;
			if (provider_id == NSTAT_PROVIDER_TCP_KERNEL || provider_id == NSTAT_PROVIDER_UDP_KERNEL) {
				tucookie = (struct nstat_tucookie *)src->nts_cookie;
				if (tucookie->inp == inp) {
					break;
				}
			}
		}

		if (src) {
			result = nstat_client_send_goodbye(client, src);

			TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
			TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		nstat_client_cleanup_source(NULL, src, TRUE);
	}
}

__private_extern__ void
nstat_pcb_event(struct inpcb *inp, u_int64_t event)
{
	nstat_client *client;
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
	NSTAT_LOCK_EXCLUSIVE();
	for (client = nstat_clients; client; client = client->ntc_next) {
		if (((client->ntc_provider_filters[NSTAT_PROVIDER_TCP_KERNEL].npf_events & event) == 0) &&
		    ((client->ntc_provider_filters[NSTAT_PROVIDER_UDP_KERNEL].npf_events & event) == 0)) {
			continue;
		}
		TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
		{
			provider_id = src->nts_provider->nstat_provider_id;
			if (provider_id == NSTAT_PROVIDER_TCP_KERNEL || provider_id == NSTAT_PROVIDER_UDP_KERNEL) {
				tucookie = (struct nstat_tucookie *)src->nts_cookie;
				if (tucookie->inp == inp) {
					break;
				}
			}
		}

		if (src && ((client->ntc_provider_filters[provider_id].npf_events & event) != 0)) {
			result = nstat_client_send_event(client, src, event);
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
}


__private_extern__ void
nstat_pcb_cache(struct inpcb *inp)
{
	nstat_client *client;
	nstat_src *src;
	struct nstat_tucookie *tucookie;

	if (inp == NULL || nstat_udp_watchers == 0 ||
	    inp->inp_nstat_refcnt == 0) {
		return;
	}
	VERIFY(SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP);
	NSTAT_LOCK_EXCLUSIVE();
	for (client = nstat_clients; client; client = client->ntc_next) {
		TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
		{
			tucookie = (struct nstat_tucookie *)src->nts_cookie;
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
	}
	NSTAT_UNLOCK_EXCLUSIVE();
}

__private_extern__ void
nstat_pcb_invalidate_cache(struct inpcb *inp)
{
	nstat_client *client;
	nstat_src *src;
	struct nstat_tucookie *tucookie;

	if (inp == NULL || nstat_udp_watchers == 0 ||
	    inp->inp_nstat_refcnt == 0) {
		return;
	}
	VERIFY(SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP);
	NSTAT_LOCK_EXCLUSIVE();
	for (client = nstat_clients; client; client = client->ntc_next) {
		TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
		{
			tucookie = (struct nstat_tucookie *)src->nts_cookie;
			if (tucookie->inp == inp) {
				tucookie->cached = false;
				break;
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
}

static errno_t
nstat_tcp_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *__sized_by(len)data,
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
		strbufcpy(desc->cc_algo, CC_ALGO(tp)->name);
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
		proc_best_name_for_pid(desc->pid, desc->pname, sizeof(desc->pname));
		if (desc->pname[0] == 0) {
			strbufcpy(desc->pname, tucookie->pname);
		} else {
			desc->pname[sizeof(desc->pname) - 1] = 0;
			strbufcpy(tucookie->pname, desc->pname);
		}
		memcpy(desc->uuid, so->last_uuid, sizeof(so->last_uuid));
		memcpy(desc->vuuid, so->so_vuuid, sizeof(so->so_vuuid));
		if (so->so_flags & SOF_DELEGATED) {
			desc->eupid = so->e_upid;
			desc->epid = so->e_pid;
			memcpy(desc->euuid, so->e_uuid, sizeof(so->e_uuid));
		} else if (!uuid_is_null(so->so_ruuid)) {
			memcpy(desc->euuid, so->so_ruuid, sizeof(so->so_ruuid));
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
						if ((filter->npf_flags & NSTAT_FILTER_ACCEPT_COMPANIONLINK_BT) &&
						    (inp->inp_btstat->rxbytes || inp->inp_btstat->txbytes)) {
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

	case NSTAT_EXTENDED_UPDATE_TYPE_BLUETOOTH_COUNTS:
		return nstat_inp_bluetooth_counts(inp, (nstat_interface_counts *)buf, len);

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
	nstat_client            *client,
	nstat_msg_add_all_srcs  *req)
{
	// There is a tricky issue around getting all UDP sockets added once
	// and only once.  nstat_udp_new_pcb() is called prior to the new item
	// being placed on any lists where it might be found.
	// By locking the udpinfo.ipi_lock prior to marking the client as a watcher,
	// it should be impossible for a new socket to be added twice.
	// On the other hand, there is still a timing issue where a new socket
	// results in a call to nstat_udp_new_pcb() before this watcher
	// is instantiated and yet the socket doesn't make it into ipi_listhead
	// prior to the scan. <rdar://problem/30361716>

	errno_t result;

	lck_rw_lock_shared(&udbinfo.ipi_lock);
	result = nstat_set_provider_filter(client, req);

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
			if (nstat_client_source_add(0, client, &nstat_udp_provider,
			    cookie, NSTAT_LOCK_NOTHELD) != 0) {
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
	__unused nstat_client    *client)
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
	NSTAT_LOCK_EXCLUSIVE();
	nstat_client     *client;
	for (client = nstat_clients; client; client = client->ntc_next) {
		if ((client->ntc_watching & (1 << NSTAT_PROVIDER_UDP_KERNEL)) != 0) {
			// this client is watching udp
			// acquire a reference for it
			cookie = nstat_tucookie_alloc_ref_locked(inp);
			if (cookie == NULL) {
				continue;
			}
			// add the source, if that fails, release the reference
			if (nstat_client_source_add(0, client,
			    &nstat_udp_provider, cookie, NSTAT_LOCK_HELD) != 0) {
				nstat_tucookie_release_locked(cookie);
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
	socket_unlock(inp->inp_socket, 0);
}

static errno_t
nstat_udp_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *__sized_by(len)data,
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
		proc_best_name_for_pid(desc->pid, desc->pname, sizeof(desc->pname));
		if (desc->pname[0] == 0) {
			strbufcpy(desc->pname, tucookie->pname);
		} else {
			desc->pname[sizeof(desc->pname) - 1] = 0;
			strbufcpy(tucookie->pname, desc->pname);
		}
		memcpy(desc->uuid, so->last_uuid, sizeof(so->last_uuid));
		memcpy(desc->vuuid, so->so_vuuid, sizeof(so->so_vuuid));
		if (so->so_flags & SOF_DELEGATED) {
			desc->eupid = so->e_upid;
			desc->epid = so->e_pid;
			memcpy(desc->euuid, so->e_uuid, sizeof(so->e_uuid));
		} else if (!uuid_is_null(so->so_ruuid)) {
			memcpy(desc->euuid, so->so_ruuid, sizeof(so->so_ruuid));
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

	case NSTAT_EXTENDED_UPDATE_TYPE_BLUETOOTH_COUNTS:
		return nstat_inp_bluetooth_counts(inp, (nstat_interface_counts *)buf, len);

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
	void                    *__sized_by(len)data,
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
		strbufcpy(desc->pname, procdetails->pdet_procname);
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
		strbufcpy(desc->pname, procdetails->pdet_procname);
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
		strbufcpy(desc->pname, procdetails->pdet_procname);
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
		u_int32_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL)) {
			if ((filter->npf_flags & ifflags) == 0) {
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
nstat_userland_extensions(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *__sized_by(len)buf, size_t len)
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
		u_int32_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL)) {
			if ((filter->npf_flags & ifflags) == 0) {
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
		u_int32_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, NULL, NULL, NULL)) {
			if ((filter->npf_flags & ifflags) == 0) {
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
	nstat_client            *client,
	nstat_msg_add_all_srcs  *req,
	nstat_provider_type_t   nstat_provider_type,
	nstat_provider          *nstat_provider,
	u_int32_t               *proto_watcher_cnt)
{
	errno_t result;

	NSTAT_LOCK_EXCLUSIVE();
	result = nstat_set_provider_filter(client, req);

	if (result == 0) {
		struct nstat_tu_shadow *shad;

		OSIncrementAtomic(proto_watcher_cnt);

		TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
			assert(shad->shad_magic == TU_SHADOW_MAGIC);

			if ((shad->shad_provider == nstat_provider_type) && (shad->shad_live)) {
				result = nstat_client_source_add(0, client, nstat_provider, shad, NSTAT_LOCK_HELD);
				if (result != 0) {
					NSTAT_LOG_ERROR("nstat_client_source_add returned %d for "
					    "provider type: %d", result, nstat_provider_type);
					break;
				}
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	return result;
}

static errno_t
nstat_userland_tcp_add_watcher(
	nstat_client            *client,
	nstat_msg_add_all_srcs  *req)
{
	return nstat_userland_protocol_add_watcher(client, req, NSTAT_PROVIDER_TCP_USERLAND,
	           &nstat_userland_tcp_provider, &nstat_userland_tcp_watchers);
}

static errno_t
nstat_userland_udp_add_watcher(
	nstat_client            *client,
	nstat_msg_add_all_srcs *req)
{
	return nstat_userland_protocol_add_watcher(client, req, NSTAT_PROVIDER_UDP_USERLAND,
	           &nstat_userland_udp_provider, &nstat_userland_udp_watchers);
}

static errno_t
nstat_userland_quic_add_watcher(
	nstat_client            *client,
	nstat_msg_add_all_srcs  *req)
{
	return nstat_userland_protocol_add_watcher(client, req, NSTAT_PROVIDER_QUIC_USERLAND,
	           &nstat_userland_quic_provider, &nstat_userland_quic_watchers);
}

static void
nstat_userland_tcp_remove_watcher(
	__unused nstat_client    *client)
{
	OSDecrementAtomic(&nstat_userland_tcp_watchers);
}

static void
nstat_userland_udp_remove_watcher(
	__unused nstat_client    *client)
{
	OSDecrementAtomic(&nstat_userland_udp_watchers);
}

static void
nstat_userland_quic_remove_watcher(
	__unused nstat_client    *client)
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
		NSTAT_LOG_ERROR("incorrect provider is supplied, %d", provider_id);
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

	NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_tu_shad_allocs);
	NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(nstat_global_tu_shad_current, nstat_global_tu_shad_max);

	NSTAT_LOCK_EXCLUSIVE();
	nstat_client *client;

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

	for (client = nstat_clients; client; client = client->ntc_next) {
		if ((client->ntc_watching & (1 << provider_id)) != 0) {
			// this client is watching tcp/udp/quic userland
			// Link to it.
			int result = nstat_client_source_add(0, client, provider, shad, NSTAT_LOCK_HELD);
			if (result != 0) {
				// There should be some kind of statistics for failures like this.
				// <rdar://problem/31377195> The kernel ntstat component should keep some
				// internal counters reflecting operational state for eventual AWD reporting
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

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

	NSTAT_LOCK_EXCLUSIVE();
	if (nstat_userland_udp_watchers != 0 ||
	    nstat_userland_tcp_watchers != 0 ||
	    nstat_userland_quic_watchers != 0) {
		nstat_client *client;
		errno_t result;

		for (client = nstat_clients; client; client = client->ntc_next) {
			TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
			{
				if (shad == (struct nstat_tu_shadow *)src->nts_cookie) {
					nstat_provider_id_t provider_id = src->nts_provider->nstat_provider_id;
					if (provider_id == NSTAT_PROVIDER_TCP_USERLAND ||
					    provider_id == NSTAT_PROVIDER_UDP_USERLAND ||
					    provider_id == NSTAT_PROVIDER_QUIC_USERLAND) {
						break;
					}
				}
			}

			if (src) {
				result = nstat_client_send_goodbye(client, src);

				TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
				TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
			}
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

	NSTAT_UNLOCK_EXCLUSIVE();

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		nstat_client_cleanup_source(NULL, src, TRUE);
	}
	nstat_release_procdetails(shad->shad_procdetails);
	shad->shad_magic = TU_SHADOW_UNMAGIC;
	NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_tu_shad_current);
	kfree_type(struct nstat_tu_shadow, shad);
}

static void
ntstat_userland_stats_event_locked(
	struct nstat_tu_shadow *shad,
	uint64_t event)
{
	nstat_client *client;
	nstat_src *src;
	errno_t result;
	nstat_provider_id_t provider_id;

	NSTAT_ASSERT_LOCKED_EXCLUSIVE();

	if (nstat_userland_udp_watchers != 0 || nstat_userland_tcp_watchers != 0 || nstat_userland_quic_watchers != 0) {
		for (client = nstat_clients; client; client = client->ntc_next) {
			if (((client->ntc_provider_filters[NSTAT_PROVIDER_TCP_USERLAND].npf_events & event) == 0) &&
			    ((client->ntc_provider_filters[NSTAT_PROVIDER_UDP_USERLAND].npf_events & event) == 0) &&
			    ((client->ntc_provider_filters[NSTAT_PROVIDER_QUIC_USERLAND].npf_events & event) == 0)) {
				continue;
			}
			TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link) {
				provider_id = src->nts_provider->nstat_provider_id;
				if (provider_id == NSTAT_PROVIDER_TCP_USERLAND || provider_id == NSTAT_PROVIDER_UDP_USERLAND ||
				    provider_id == NSTAT_PROVIDER_QUIC_USERLAND) {
					if (shad == (struct nstat_tu_shadow *)src->nts_cookie) {
						break;
					}
				}
			}
			if (src && ((client->ntc_provider_filters[provider_id].npf_events & event) != 0)) {
				result = nstat_client_send_event(client, src, event);
			}
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

		NSTAT_LOCK_EXCLUSIVE();
		if (nstat_userland_udp_watchers != 0 ||
		    nstat_userland_tcp_watchers != 0 ||
		    nstat_userland_quic_watchers != 0) {
			nstat_client *client;
			errno_t result;

			for (client = nstat_clients; client; client = client->ntc_next) {
				TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
				{
					if (shad == (struct nstat_tu_shadow *)src->nts_cookie) {
						break;
					}
				}

				if (src) {
					if (!(src->nts_filter & NSTAT_FILTER_TCP_NO_EARLY_CLOSE)) {
						result = nstat_client_send_goodbye(client, src);

						TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
						TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
					}
				}
			}
		}
		NSTAT_UNLOCK_EXCLUSIVE();

		while ((src = TAILQ_FIRST(&dead_list))) {
			TAILQ_REMOVE(&dead_list, src, nts_client_link);
			nstat_client_cleanup_source(NULL, src, TRUE);
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

	NSTAT_LOCK_EXCLUSIVE();

	if (nstat_userland_udp_watchers != 0 ||
	    nstat_userland_tcp_watchers != 0 ||
	    nstat_userland_quic_watchers != 0) {
		nstat_client *client;
		errno_t result;

		for (client = nstat_clients; client; client = client->ntc_next) {
			TAILQ_FOREACH_SAFE(src, &client->ntc_src_queue, nts_client_link, tmpsrc)
			{
				nstat_provider_id_t provider_id = src->nts_provider->nstat_provider_id;
				if (provider_id == NSTAT_PROVIDER_TCP_USERLAND ||
				    provider_id == NSTAT_PROVIDER_UDP_USERLAND ||
				    provider_id == NSTAT_PROVIDER_QUIC_USERLAND) {
					shad = (struct nstat_tu_shadow *)src->nts_cookie;
					if (shad->shad_procdetails->pdet_pid == pid) {
						result = nstat_client_send_goodbye(client, src);

						TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
						TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
					}
				}
			}
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

	NSTAT_UNLOCK_EXCLUSIVE();

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		nstat_client_cleanup_source(NULL, src, TRUE);
	}
}

errno_t
nstat_userland_mark_rnf_override(uuid_t target_fuuid, bool rnf_override)
{
	// Note that this can be called multiple times for the same process
	struct nstat_tu_shadow *shad;
	uuid_t fuuid;
	errno_t result;

	NSTAT_LOCK_EXCLUSIVE();
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

	NSTAT_UNLOCK_EXCLUSIVE();

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
	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	OSIncrementAtomic(&gshad->gshad_refcnt);
}

static void
nstat_release_gshad(
	struct nstat_generic_shadow *gshad)
{
	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	if (OSDecrementAtomic(&gshad->gshad_refcnt) == 1) {
		nstat_release_procdetails(gshad->gshad_procdetails);
		gshad->gshad_magic = NSTAT_GENERIC_SHADOW_UNMAGIC;
		NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_gshad_current);
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
	void                    *__sized_by(len)data,
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
		strbufcpy(desc->pname, procdetails->pdet_procname);
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
		strbufcpy(desc->pname, procdetails->pdet_procname);
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
				NSTAT_LOG("attempt to filter conn provider by effective pid/uuid, not supported");
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
nstat_generic_extensions(nstat_provider_cookie_t cookie, u_int32_t extension_id, void *__sized_by(len)buf, size_t len)
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
	nstat_client            *client,
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

	NSTAT_LOCK_EXCLUSIVE();
	result = nstat_set_provider_filter(client, req);

	if (result == 0) {
		struct nstat_generic_shadow *gshad;
		nstat_provider_filter *filter = &client->ntc_provider_filters[provider_id];

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
				result = nstat_client_source_add(0, client, provider, gshad, NSTAT_LOCK_HELD);
				if (result != 0) {
					NSTAT_LOG_ERROR("nstat_client_source_add returned %d for "
					    "provider type: %d", result, provider_id);
					nstat_release_gshad(gshad);
					break;
				}
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	return result;
}

static void
nstat_userland_conn_remove_watcher(
	__unused nstat_client    *client)
{
	OSDecrementAtomic(&nstat_generic_provider_watchers[NSTAT_PROVIDER_CONN_USERLAND]);
}

static void
nstat_udp_subflow_remove_watcher(
	__unused nstat_client    *client)
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
	NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_gshad_allocs);
	NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(nstat_global_gshad_current, nstat_global_gshad_max);

	NSTAT_LOCK_EXCLUSIVE();
	nstat_client     *client;

	// Even if there are no watchers, we save the shadow structure
	TAILQ_INSERT_HEAD(&nstat_gshad_head, gshad, gshad_link);

	for (client = nstat_clients; client; client = client->ntc_next) {
		if ((client->ntc_watching & (1 << provider_id)) != 0) {
			// Does this client want an initial filtering to be made?
			u_int64_t npf_flags = client->ntc_provider_filters[provider->nstat_provider_id].npf_flags;
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
			int result = nstat_client_source_add(0, client, provider, gshad, NSTAT_LOCK_HELD);
			if (result != 0) {
				// There should be some kind of statistics for failures like this.
				// <rdar://problem/31377195> The kernel ntstat component should keep some
				// internal counters reflecting operational state for eventual AWD reporting
				nstat_release_gshad(gshad);
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

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
		NSTAT_LOG_ERROR("called with null reference");
		return;
	}

	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	if (gshad->gshad_magic != NSTAT_GENERIC_SHADOW_MAGIC) {
		NSTAT_LOG_ERROR("called with incorrect shadow magic 0x%x", gshad->gshad_magic);
	}

	TAILQ_INIT(&dead_list);

	NSTAT_LOCK_EXCLUSIVE();

	TAILQ_REMOVE(&nstat_gshad_head, gshad, gshad_link);

	int32_t num_srcs = gshad->gshad_refcnt - 1;
	if ((nstat_generic_provider_watchers[gshad->gshad_provider] != 0) && (num_srcs > 0)) {
		nstat_client *client;
		errno_t result;

		for (client = nstat_clients; client; client = client->ntc_next) {
			// Only scan further if this client is watching
			if ((client->ntc_watching & (1 << gshad->gshad_provider)) != 0) {
				TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
				{
					if ((gshad == (struct nstat_generic_shadow *)src->nts_cookie) &&
					    (gshad->gshad_provider == src->nts_provider->nstat_provider_id)) {
						break;
					}
				}
				if (src) {
					result = nstat_client_send_goodbye(client, src);
					// There is currently no recovery possible from failure to send,
					// so no need to check the return code.
					// rdar://28312774 (Scalability and resilience issues in ntstat.c)

					TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
					TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
					--num_srcs;
				}

				// Performance optimization, don't scan full lists if no chance of presence
				if (num_srcs == 0) {
					break;
				}
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		nstat_client_cleanup_source(NULL, src, TRUE);
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
		NSTAT_LOG_ERROR("called with null reference");
		return;
	}

	assert(gshad->gshad_magic == NSTAT_GENERIC_SHADOW_MAGIC);

	if (gshad->gshad_magic != NSTAT_GENERIC_SHADOW_MAGIC) {
		NSTAT_LOG_ERROR("called with incorrect shadow magic 0x%x", gshad->gshad_magic);
	}

	NSTAT_LOCK_EXCLUSIVE();

	if (nstat_generic_provider_watchers[gshad->gshad_provider] != 0) {
		nstat_client *client;
		errno_t result;
		nstat_provider_id_t provider_id = gshad->gshad_provider;

		for (client = nstat_clients; client; client = client->ntc_next) {
			// Only scan further if this client is watching and has interest in the event
			// or the client has requested "boring" unchanged status to be ignored
			if (((client->ntc_watching & (1 << provider_id)) != 0) &&
			    (((client->ntc_provider_filters[provider_id].npf_events & event) != 0) ||
			    ((client->ntc_provider_filters[provider_id].npf_flags & NSTAT_FILTER_SUPPRESS_BORING_FLAGS) != 0))) {
				TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
				{
					if (gshad == (struct nstat_generic_shadow *)src->nts_cookie) {
						break;
					}
				}

				if (src) {
					src->nts_reported = false;
					if ((client->ntc_provider_filters[provider_id].npf_events & event) != 0) {
						result = nstat_client_send_event(client, src, event);
						// There is currently no recovery possible from failure to send,
						// so no need to check the return code.
						// rdar://28312774 (Scalability and resilience issues in ntstat.c)
					}
				}
			}
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
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
	nstat_client *client;
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
		NSTAT_LOCK_EXCLUSIVE();
		for (client = nstat_clients; client; client = client->ntc_next) {
			TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
			{
				if (src->nts_provider != &nstat_ifnet_provider) {
					continue;
				}
				nstat_client_send_description(client, src, 0, 0);
			}
		}
		NSTAT_UNLOCK_EXCLUSIVE();
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
	nstat_client *client;
	nstat_src *src;
	uint64_t minthreshold = UINT64_MAX;

	/*
	 * Find all the clients that requested a threshold
	 * for this ifnet and re-calculate if_data_threshold.
	 */
	NSTAT_LOCK_SHARED();
	for (client = nstat_clients; client; client = client->ntc_next) {
		TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
		{
			/* Skip the provider we are about to detach. */
			if (src->nts_provider != &nstat_ifnet_provider ||
			    src->nts_cookie == cookie) {
				continue;
			}
			ifcookie = (struct nstat_ifnet_cookie *)src->nts_cookie;
			if (ifcookie->threshold < minthreshold) {
				minthreshold = ifcookie->threshold;
			}
		}
	}
	NSTAT_UNLOCK_SHARED();
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

/* Some thresholds to determine Low Internet mode */
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
		if (nstat_debug != 0) {
			NSTAT_LOG_DEBUG("Reporting LIM stats for ifindex %u", ifp->if_index);
		}
		ifnet_lock_done(ifp);
		nstat_sysinfo_send_data(&data);
	}
	ifnet_head_done();
}

static errno_t
nstat_ifnet_copy_descriptor(
	nstat_provider_cookie_t cookie,
	void                    *__sized_by(len)data,
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
	nstat_client *client;
	nstat_src *src;
	struct ifnet *ifp;
	struct nstat_ifnet_cookie *ifcookie;

	NSTAT_LOCK_EXCLUSIVE();
	for (client = nstat_clients; client; client = client->ntc_next) {
		TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
		{
			if (src->nts_provider != &nstat_ifnet_provider) {
				continue;
			}
			ifcookie = (struct nstat_ifnet_cookie *)src->nts_cookie;
			ifp = ifcookie->ifp;
			if (ifp->if_index != ifindex) {
				continue;
			}
			nstat_client_send_counts(client, src, 0, 0, NULL);
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
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
nstat_set_keyval_string(nstat_sysinfo_keyval *kv, int key, u_int8_t *__counted_by(len)buf,
    u_int32_t len)
{
	kv->nstat_sysinfo_key = key;
	kv->nstat_sysinfo_flags = NSTAT_SYSINFO_FLAG_STRING;
	kv->nstat_sysinfo_valsize = len;
	bcopy(buf, kv->u.nstat_sysinfo_string, kv->nstat_sysinfo_valsize);
}

static void
nstat_sysinfo_send_data_internal(
	nstat_client *client,
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
	case NSTAT_SYSINFO_TCP_STATS:
		nkeyvals = NSTAT_SYSINFO_TCP_STATS_COUNT;
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

	kv = nstat_sysinfo_get_keyvals(syscnt);

	switch (data->flags) {
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
	case NSTAT_SYSINFO_LIM_STATS:
	{
		nstat_set_keyval_string(&kv[i++],
		    NSTAT_SYSINFO_LIM_IFNET_SIGNATURE,
		    data->u.lim_stats.ifnet_signature,
		    min(data->u.lim_stats.ifnet_siglen, NSTAT_SYSINFO_KEYVAL_STRING_MAXSIZE));
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

		result = ctl_enqueuedata(client->ntc_kctl,
		    client->ntc_unit, syscnt, finalsize, CTL_DATA_EOR);
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
	if (nstat_debug != 0) {
		NSTAT_LOG_DEBUG("Sending stats report for %x", data->flags);
	}

	nstat_client *client;

	NSTAT_LOCK_EXCLUSIVE();
	for (client = nstat_clients; client; client = client->ntc_next) {
		if ((client->ntc_flags & NSTAT_FLAG_SYSINFO_SUBSCRIBED) != 0) {
			nstat_sysinfo_send_data_internal(client, data);
		}
	}
	NSTAT_UNLOCK_EXCLUSIVE();
}

static void
nstat_sysinfo_generate_report(void)
{
	tcp_report_stats();
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

static errno_t  nstat_client_connect(kern_ctl_ref kctl, struct sockaddr_ctl *sac, void **uinfo);
static errno_t  nstat_client_disconnect(kern_ctl_ref kctl, u_int32_t unit, void *uinfo);
static errno_t  nstat_client_send(kern_ctl_ref kctl, u_int32_t unit, void *uinfo, mbuf_t m, int flags);

static errno_t
nstat_enqueue_success(
	uint64_t context,
	nstat_client *client,
	u_int16_t flags)
{
	nstat_msg_hdr success;
	errno_t result;

	bzero(&success, sizeof(success));
	success.context = context;
	success.type = NSTAT_MSG_TYPE_SUCCESS;
	success.length = sizeof(success);
	success.flags = flags;
	result = ctl_enqueuedata(client->ntc_kctl, client->ntc_unit, &success,
	    sizeof(success), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		if (nstat_debug != 0) {
			NSTAT_LOG_ERROR("could not enqueue success message %d", result);
		}
		nstat_stats.nstat_successmsgfailures += 1;
	}
	return result;
}

static errno_t
nstat_client_send_event(
	nstat_client    *client,
	nstat_src       *src,
	u_int64_t       event)
{
	errno_t result = ENOTSUP;
	int failed = 0;

	if (nstat_client_reporting_allowed(client, src, 0)) {
		if ((client->ntc_flags & NSTAT_FLAG_SUPPORTS_UPDATES) != 0) {
			result = nstat_client_send_update(client, src, 0, event, 0, NULL);
			if (result != 0) {
				failed = 1;
				if (nstat_debug != 0) {
					NSTAT_LOG_ERROR("nstat_client_send_event() %d", result);
				}
			}
		} else {
			if (nstat_debug != 0) {
				NSTAT_LOG_ERROR("nstat_client_send_event() used when updates not supported");
			}
		}
	}
	return result;
}

static errno_t
nstat_client_send_goodbye(
	nstat_client    *client,
	nstat_src       *src)
{
	errno_t result = 0;
	int failed = 0;
	u_int16_t hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_FILTER;

	if (nstat_client_reporting_allowed(client, src, (src->nts_reported)? NSTAT_FILTER_SUPPRESS_BORING_CLOSE: 0)) {
		hdr_flags = 0;
		if ((client->ntc_flags & NSTAT_FLAG_SUPPORTS_UPDATES) != 0) {
			result = nstat_client_send_update(client, src, 0, 0, NSTAT_MSG_HDR_FLAG_CLOSING, NULL);
			if (result != 0) {
				failed = 1;
				hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_DROP;
				if (nstat_debug != 0) {
					NSTAT_LOG_ERROR("nstat_client_send_update() %d", result);
				}
			}
		} else {
			// send one last counts notification
			result = nstat_client_send_counts(client, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING, NULL);
			if (result != 0) {
				failed = 1;
				hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_DROP;
				if (nstat_debug != 0) {
					NSTAT_LOG_ERROR("nstat_client_send_counts() %d", result);
				}
			}

			// send a last description
			result = nstat_client_send_description(client, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING);
			if (result != 0) {
				failed = 1;
				hdr_flags = NSTAT_MSG_HDR_FLAG_CLOSED_AFTER_DROP;
				if (nstat_debug != 0) {
					NSTAT_LOG_ERROR("nstat_client_send_description() %d", result);
				}
			}
		}
	}

	// send the source removed notification
	result = nstat_client_send_removed(client, src, hdr_flags);
	if (result != 0 && nstat_debug) {
		failed = 1;
		if (nstat_debug != 0) {
			NSTAT_LOG_ERROR("nstat_client_send_removed() %d", result);
		}
	}

	if (failed != 0) {
		nstat_stats.nstat_control_send_goodbye_failures++;
	}


	return result;
}

static errno_t
nstat_flush_accumulated_msgs(
	nstat_client     *client)
{
	errno_t result = 0;
	if (client->ntc_accumulated != NULL && mbuf_len(client->ntc_accumulated) > 0) {
		mbuf_pkthdr_setlen(client->ntc_accumulated, mbuf_len(client->ntc_accumulated));
		result = ctl_enqueuembuf(client->ntc_kctl, client->ntc_unit, client->ntc_accumulated, CTL_DATA_EOR);
		if (result != 0) {
			nstat_stats.nstat_flush_accumulated_msgs_failures++;
			if (nstat_debug != 0) {
				NSTAT_LOG_ERROR("ctl_enqueuembuf failed: %d", result);
			}
			mbuf_freem(client->ntc_accumulated);
		}
		client->ntc_accumulated = NULL;
	}
	return result;
}

static errno_t
nstat_accumulate_msg(
	nstat_client    *client,
	uint8_t         *__sized_by(length) msg,
	size_t          length)
{
	assert(length <= MAX_NSTAT_MSG_HDR_LENGTH);

	if (client->ntc_accumulated && mbuf_trailingspace(client->ntc_accumulated) < length) {
		// Will send the current mbuf
		nstat_flush_accumulated_msgs(client);
	}

	errno_t result = 0;

	if (client->ntc_accumulated == NULL) {
		unsigned int one = 1;
		if (mbuf_allocpacket(MBUF_DONTWAIT, NSTAT_MAX_MSG_SIZE, &one, &client->ntc_accumulated) != 0) {
			if (nstat_debug != 0) {
				NSTAT_LOG_ERROR("mbuf_allocpacket failed");
			}
			result = ENOMEM;
		} else {
			mbuf_setlen(client->ntc_accumulated, 0);
		}
	}

	if (result == 0) {
		result = mbuf_copyback(client->ntc_accumulated, mbuf_len(client->ntc_accumulated),
		    length, msg, MBUF_DONTWAIT);
	}

	if (result != 0) {
		nstat_flush_accumulated_msgs(client);
		if (nstat_debug != 0) {
			NSTAT_LOG_ERROR("resorting to ctl_enqueuedata");
		}
		result = ctl_enqueuedata(client->ntc_kctl, client->ntc_unit, msg, length, CTL_DATA_EOR);
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
	nstat_client *client;
	nstat_src  *src, *tmpsrc;
	tailq_head_nstat_src dead_list;
	TAILQ_INIT(&dead_list);

	NSTAT_LOCK_EXCLUSIVE();

	nstat_idle_time = 0;

	for (client = nstat_clients; client; client = client->ntc_next) {
		TAILQ_FOREACH_SAFE(src, &client->ntc_src_queue, nts_client_link, tmpsrc)
		{
			if (src->nts_provider->nstat_gone(src->nts_cookie)) {
				errno_t result;

				// Pull it off the list
				NSTAT_NOTE_SRC(nstat_src_gone_idlecheck, client, src);
				TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);

				result = nstat_client_send_goodbye(client, src);

				// Put this on the list to release later
				TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
			}
		}
	}

	if (nstat_clients) {
		clock_interval_to_deadline(60, NSEC_PER_SEC, &nstat_idle_time);
		thread_call_func_delayed((thread_call_func_t)nstat_idle_check, NULL, nstat_idle_time);
	}

	NSTAT_UNLOCK_EXCLUSIVE();

	/* Generate any system level reports, if needed */
	nstat_sysinfo_generate_report();

	// Release the sources now that we aren't holding lots of locks
	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_src_idlecheck_gone);
		nstat_client_cleanup_source(NULL, src, FALSE);
	}

	nstat_prune_procdetails();
}

static void
nstat_client_register(void)
{
	// Register the control
	struct kern_ctl_reg     nstat_control;
	bzero(&nstat_control, sizeof(nstat_control));
	strlcpy(nstat_control.ctl_name, NET_STAT_CONTROL_NAME, sizeof(nstat_control.ctl_name));
	nstat_control.ctl_flags = CTL_FLAG_REG_EXTENDED | CTL_FLAG_REG_CRIT;
	nstat_control.ctl_sendsize = nstat_sendspace;
	nstat_control.ctl_recvsize = nstat_recvspace;
	nstat_control.ctl_connect = nstat_client_connect;
	nstat_control.ctl_disconnect = nstat_client_disconnect;
	nstat_control.ctl_send = nstat_client_send;

	ctl_register(&nstat_control, &nstat_ctlref);
}

static void
nstat_client_cleanup_source(
	nstat_client        *client,
	struct nstat_src    *src,
	boolean_t           locked)
{
	errno_t result;

	if (client) {
		result = nstat_client_send_removed(client, src, 0);
		if (result != 0) {
			nstat_stats.nstat_control_cleanup_source_failures++;
			if (nstat_debug != 0) {
				NSTAT_LOG_ERROR("nstat_client_send_removed() %d", result);
			}
		}
	}
	// Cleanup the source if we found it.
	src->nts_provider->nstat_release(src->nts_cookie, locked);
	NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_src_current);
	kfree_type(struct nstat_src, src);
}

static bool
nstat_client_reporting_allowed(
	nstat_client *client,
	nstat_src *src,
	u_int64_t suppression_flags)
{
	if (src->nts_provider->nstat_reporting_allowed == NULL) {
		return TRUE;
	}

	return src->nts_provider->nstat_reporting_allowed(src->nts_cookie,
	           &client->ntc_provider_filters[src->nts_provider->nstat_provider_id], suppression_flags);
}


static errno_t
nstat_client_connect(
	kern_ctl_ref        kctl,
	struct sockaddr_ctl *sac,
	void                **uinfo)
{
	nstat_client *client = kalloc_type(nstat_client,
	    Z_WAITOK | Z_ZERO);
	if (client == NULL) {
		return ENOMEM;
	}

	lck_mtx_init(&client->ntc_user_mtx, &nstat_lck_grp, NULL);
	client->ntc_kctl = kctl;
	client->ntc_unit = sac->sc_unit;
	client->ntc_flags = NSTAT_FLAG_REQCOUNTS;
	client->ntc_procdetails = nstat_retain_curprocdetails();
	*uinfo = client;

	NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_client_allocs);
	NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(nstat_global_client_current, nstat_global_client_max);
#if NSTAT_TRACE_ENABLED
	client->ntc_trace = (nstat_cyclic_trace *)kalloc_data(sizeof(nstat_cyclic_trace), Z_WAITOK | Z_ZERO);
#endif
	NSTAT_LOCK_EXCLUSIVE();
	client->ntc_next = nstat_clients;
	nstat_clients = client;

	if (nstat_idle_time == 0) {
		clock_interval_to_deadline(60, NSEC_PER_SEC, &nstat_idle_time);
		thread_call_func_delayed((thread_call_func_t)nstat_idle_check, NULL, nstat_idle_time);
	}

	merge_current_event_filters();
	NSTAT_UNLOCK_EXCLUSIVE();

	return 0;
}

static errno_t
nstat_client_disconnect(
	__unused kern_ctl_ref   kctl,
	__unused u_int32_t      unit,
	void                    *uinfo)
{
	u_int32_t   watching;
	nstat_client *client = (nstat_client*)uinfo;
	tailq_head_nstat_src cleanup_list;
	nstat_src *src;

	TAILQ_INIT(&cleanup_list);

	// pull it out of the global list of clients
	NSTAT_LOCK_EXCLUSIVE();
	nstat_client     **clientpp;
	for (clientpp = &nstat_clients; *clientpp; clientpp = &(*clientpp)->ntc_next) {
		if (*clientpp == client) {
			*clientpp = client->ntc_next;
			break;
		}
	}
	merge_current_event_filters();

	// Stop watching for sources
	nstat_provider  *provider;
	watching = client->ntc_watching;
	client->ntc_watching = 0;
	for (provider = nstat_providers; provider && watching; provider = provider->next) {
		if ((watching & (1 << provider->nstat_provider_id)) != 0) {
			watching &= ~(1 << provider->nstat_provider_id);
			provider->nstat_watcher_remove(client);
		}
	}

	// set cleanup flags
	client->ntc_flags |= NSTAT_FLAG_CLEANUP;

	if (client->ntc_accumulated) {
		mbuf_freem(client->ntc_accumulated);
		client->ntc_accumulated = NULL;
	}

	// Copy out the list of sources
	TAILQ_CONCAT(&cleanup_list, &client->ntc_src_queue, nts_client_link);

	NSTAT_UNLOCK_EXCLUSIVE();

	while ((src = TAILQ_FIRST(&cleanup_list))) {
		TAILQ_REMOVE(&cleanup_list, src, nts_client_link);
		nstat_client_cleanup_source(NULL, src, FALSE);
	}

	lck_mtx_destroy(&client->ntc_user_mtx, &nstat_lck_grp);
	nstat_release_procdetails(client->ntc_procdetails);
	nstat_accumulate_client_metrics(client);
#if NSTAT_TRACE_ENABLED
	if (client->ntc_trace != NULL) {
		kfree_data(client->ntc_trace, sizeof(nstat_cyclic_trace));
	}
#endif
	NSTAT_GLOBAL_COUNT_DECREMENT(nstat_global_client_current);
	kfree_type(struct nstat_client, client);

	return 0;
}

static nstat_src_ref_t
nstat_client_next_src_ref(
	nstat_client     *client)
{
	return ++client->ntc_next_srcref;
}

static errno_t
nstat_client_send_counts(
	nstat_client        *client,
	nstat_src           *src,
	unsigned long long  context,
	u_int16_t           hdr_flags,
	int                 *gone)
{
	nstat_msg_src_counts counts;
	errno_t result = 0;

	/* Some providers may not have any counts to send */
	if (src->nts_provider->nstat_counts == NULL) {
		return 0;
	}

	bzero(&counts, sizeof(counts));
	counts.hdr.type = NSTAT_MSG_TYPE_SRC_COUNTS;
	counts.hdr.length = sizeof(counts);
	counts.hdr.flags = hdr_flags;
	counts.hdr.context = context;
	counts.srcref = src->nts_srcref;
	counts.event_flags = 0;

	if (src->nts_provider->nstat_counts(src->nts_cookie, &counts.counts, gone) == 0) {
		if ((src->nts_filter & NSTAT_FILTER_NOZEROBYTES) &&
		    counts.counts.nstat_rxbytes == 0 &&
		    counts.counts.nstat_txbytes == 0) {
			result = EAGAIN;
		} else {
			result = ctl_enqueuedata(client->ntc_kctl,
			    client->ntc_unit, &counts, sizeof(counts),
			    CTL_DATA_EOR);
			if (result != 0) {
				nstat_stats.nstat_sendcountfailures += 1;
			}
		}
	}
	return result;
}

static errno_t
nstat_client_append_counts(
	nstat_client    *client,
	nstat_src       *src,
	int             *gone)
{
	/* Some providers may not have any counts to send */
	if (!src->nts_provider->nstat_counts) {
		return 0;
	}

	nstat_msg_src_counts counts;
	bzero(&counts, sizeof(counts));
	counts.hdr.type = NSTAT_MSG_TYPE_SRC_COUNTS;
	counts.hdr.length = sizeof(counts);
	counts.srcref = src->nts_srcref;
	counts.event_flags = 0;

	errno_t result = 0;
	result = src->nts_provider->nstat_counts(src->nts_cookie, &counts.counts, gone);
	if (result != 0) {
		return result;
	}

	if ((src->nts_filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
	    counts.counts.nstat_rxbytes == 0 && counts.counts.nstat_txbytes == 0) {
		return EAGAIN;
	}

	return nstat_accumulate_msg(client, (uint8_t *)&counts, sizeof(counts));
}

static int
nstat_client_send_description(
	nstat_client    *client,
	nstat_src       *src,
	u_int64_t       context,
	u_int16_t       hdr_flags)
{
	// Provider doesn't support getting the descriptor? Done.
	if (src->nts_provider->nstat_descriptor_length == 0 ||
	    src->nts_provider->nstat_copy_descriptor == NULL) {
		return EOPNOTSUPP;
	}

	// Allocate storage for the descriptor message
	mbuf_ref_t          msg;
	unsigned int    one = 1;
	size_t          size = offsetof(nstat_msg_src_description, data) + src->nts_provider->nstat_descriptor_length;
	assert(size <= MAX_NSTAT_MSG_HDR_LENGTH);

	if (mbuf_allocpacket(MBUF_DONTWAIT, size, &one, &msg) != 0) {
		return ENOMEM;
	}


	bzero(m_mtod_current(msg), size);
	mbuf_setlen(msg, size);
	mbuf_pkthdr_setlen(msg, mbuf_len(msg));

	// Query the provider for the provider specific bits
	nstat_msg_src_description *desc = mtod(msg, nstat_msg_src_description *);
	desc->hdr.context = context;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_DESC;
	desc->hdr.length = (u_int16_t)size;
	desc->hdr.flags = hdr_flags;
	desc->srcref = src->nts_srcref;
	desc->event_flags = 0;
	desc->provider = src->nts_provider->nstat_provider_id;

	uint8_t *desc_data_ptr = nstat_get_data(desc);
	errno_t result = src->nts_provider->nstat_copy_descriptor(src->nts_cookie, desc_data_ptr, src->nts_provider->nstat_descriptor_length);

	if (result != 0) {
		mbuf_freem(msg);
		return result;
	}

	result = ctl_enqueuembuf(client->ntc_kctl, client->ntc_unit, msg, CTL_DATA_EOR);
	if (result != 0) {
		nstat_stats.nstat_descriptionfailures += 1;
		mbuf_freem(msg);
	}

	return result;
}

static errno_t
nstat_client_append_description(
	nstat_client    *client,
	nstat_src       *src)
{
	size_t  size = offsetof(nstat_msg_src_description, data) + src->nts_provider->nstat_descriptor_length;
	if (size > 512 || src->nts_provider->nstat_descriptor_length == 0 ||
	    src->nts_provider->nstat_copy_descriptor == NULL) {
		return EOPNOTSUPP;
	}

	// Fill out a buffer on the stack, we will copy to the mbuf later
	u_int64_t buffer[size / sizeof(u_int64_t)  + 1]; // u_int64_t to ensure alignment
	bzero(buffer, size);

	nstat_msg_src_description *desc = (nstat_msg_src_description*)buffer;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_DESC;
	desc->hdr.length = (u_int16_t)size;
	desc->srcref = src->nts_srcref;
	desc->event_flags = 0;
	desc->provider = src->nts_provider->nstat_provider_id;

	errno_t result = 0;
	// Fill in the description
	// Query the provider for the provider specific bits
	uint8_t *desc_data_ptr = nstat_get_data(desc);
	result = src->nts_provider->nstat_copy_descriptor(src->nts_cookie, desc_data_ptr,
	    src->nts_provider->nstat_descriptor_length);
	if (result != 0) {
		return result;
	}

	return nstat_accumulate_msg(client, (uint8_t *)buffer, size);
}

static uint64_t
nstat_extension_flags_for_source(
	nstat_client    *client,
	nstat_src       *src)
{
	VERIFY(client != NULL & src != NULL);
	nstat_provider_id_t provider_id = src->nts_provider->nstat_provider_id;

	return client->ntc_provider_filters[provider_id].npf_extensions;
}

static int
nstat_client_send_update(
	nstat_client    *client,
	nstat_src       *src,
	u_int64_t       context,
	u_int64_t       event,
	u_int16_t       hdr_flags,
	int             *gone)
{
	// Provider doesn't support getting the descriptor or counts? Done.
	if ((src->nts_provider->nstat_descriptor_length == 0 ||
	    src->nts_provider->nstat_copy_descriptor == NULL) &&
	    src->nts_provider->nstat_counts == NULL) {
		return EOPNOTSUPP;
	}

	// Allocate storage for the descriptor message
	mbuf_ref_t      msg;
	unsigned int    one = 1;
	size_t          size = offsetof(nstat_msg_src_update, data) +
	    src->nts_provider->nstat_descriptor_length;
	size_t          total_extension_size = 0;
	u_int32_t       num_extensions = 0;
	u_int64_t       extension_mask = nstat_extension_flags_for_source(client, src);

	if ((extension_mask != 0) && (src->nts_provider->nstat_copy_extension != NULL)) {
		uint32_t extension_id = 0;
		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				size_t extension_size = src->nts_provider->nstat_copy_extension(src->nts_cookie, extension_id, NULL, 0);
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

	/* zero out for nstat_msg_src_update */
	bzero(m_mtod_current(msg), size);

	nstat_msg_src_update *desc = mtod(msg, nstat_msg_src_update *);
	desc->hdr.context = context;
	desc->hdr.type = (num_extensions == 0) ? NSTAT_MSG_TYPE_SRC_UPDATE :
	    NSTAT_MSG_TYPE_SRC_EXTENDED_UPDATE;
	desc->hdr.length = (u_int16_t)size;
	desc->hdr.flags = hdr_flags;
	desc->srcref = src->nts_srcref;
	desc->event_flags = event;
	desc->provider = src->nts_provider->nstat_provider_id;

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
	if (src->nts_provider->nstat_descriptor_length != 0 && src->nts_provider->nstat_copy_descriptor) {
		// Query the provider for the provider specific bits
		u_int8_t *desc_data_ptr = nstat_get_data(desc);
		result = src->nts_provider->nstat_copy_descriptor(src->nts_cookie, desc_data_ptr,
		    src->nts_provider->nstat_descriptor_length);
		if (result != 0) {
			mbuf_freem(msg);
			return result;
		}
	}

	if (num_extensions > 0) {
		nstat_msg_src_extended_item_hdr *p_extension_hdr = (nstat_msg_src_extended_item_hdr *)mtodo(msg, sizeof(nstat_msg_src_update_hdr) + src->nts_provider->nstat_descriptor_length);
		uint32_t extension_id = 0;

		bzero(p_extension_hdr, total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * num_extensions));

		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				void *buf = (void *)(p_extension_hdr + 1);
				size_t extension_size = src->nts_provider->nstat_copy_extension(src->nts_cookie, extension_id, buf, total_extension_size);
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

	if (src->nts_provider->nstat_counts) {
		result = src->nts_provider->nstat_counts(src->nts_cookie, &desc->counts, gone);
		if (result == 0) {
			if ((src->nts_filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
			    desc->counts.nstat_rxbytes == 0 && desc->counts.nstat_txbytes == 0) {
				result = EAGAIN;
			} else {
				result = ctl_enqueuembuf(client->ntc_kctl, client->ntc_unit, msg, CTL_DATA_EOR);
			}
		}
	}

	if (result != 0) {
		nstat_stats.nstat_srcupatefailures += 1;
		mbuf_freem(msg);
	} else {
		src->nts_reported = true;
	}

	return result;
}

static errno_t
nstat_client_append_update(
	nstat_client    *client,
	nstat_src       *src,
	int             *gone)
{
	if ((src->nts_provider->nstat_descriptor_length == 0 ||
	    src->nts_provider->nstat_copy_descriptor == NULL) &&
	    src->nts_provider->nstat_counts == NULL) {
		return EOPNOTSUPP;
	}

	size_t      size = offsetof(nstat_msg_src_update, data) + src->nts_provider->nstat_descriptor_length;
	size_t      total_extension_size = 0;
	u_int32_t   num_extensions = 0;
	u_int64_t   extension_mask = nstat_extension_flags_for_source(client, src);

	if ((extension_mask != 0) && (src->nts_provider->nstat_copy_extension != NULL)) {
		uint32_t extension_id = 0;
		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				size_t extension_size = src->nts_provider->nstat_copy_extension(src->nts_cookie, extension_id, NULL, 0);
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
	desc->srcref = src->nts_srcref;
	desc->event_flags = 0;
	desc->provider = src->nts_provider->nstat_provider_id;

	errno_t result = 0;
	// Fill in the description
	if (src->nts_provider->nstat_descriptor_length != 0 && src->nts_provider->nstat_copy_descriptor) {
		// Query the provider for the provider specific bits
		u_int8_t *desc_data_ptr = nstat_get_data(desc);
		result = src->nts_provider->nstat_copy_descriptor(src->nts_cookie, desc_data_ptr,
		    src->nts_provider->nstat_descriptor_length);
		if (result != 0) {
			nstat_stats.nstat_copy_descriptor_failures++;
			if (nstat_debug != 0) {
				NSTAT_LOG_ERROR("src->nts_provider->nstat_copy_descriptor: %d", result);
			}
			return result;
		}
	}

	if (num_extensions > 0) {
		nstat_msg_src_extended_item_hdr *p_extension_hdr = (nstat_msg_src_extended_item_hdr *)(void *)((char *)buffer +
		    sizeof(nstat_msg_src_update_hdr) + src->nts_provider->nstat_descriptor_length);
		uint32_t extension_id = 0;
		bzero(p_extension_hdr, total_extension_size + (sizeof(nstat_msg_src_extended_item_hdr) * num_extensions));

		for (extension_id = NSTAT_EXTENDED_UPDATE_TYPE_MIN; extension_id <= NSTAT_EXTENDED_UPDATE_TYPE_MAX; extension_id++) {
			if ((extension_mask & (1ull << extension_id)) != 0) {
				void *buf = (void *)(p_extension_hdr + 1);
				size_t extension_size = src->nts_provider->nstat_copy_extension(src->nts_cookie, extension_id, buf, total_extension_size);
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

	if (src->nts_provider->nstat_counts) {
		result = src->nts_provider->nstat_counts(src->nts_cookie, &desc->counts, gone);
		if (result != 0) {
			nstat_stats.nstat_provider_counts_failures++;
			if (nstat_debug != 0) {
				NSTAT_LOG_ERROR("src->nts_provider->nstat_counts: %d", result);
			}
			return result;
		}

		if ((src->nts_filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
		    desc->counts.nstat_rxbytes == 0 && desc->counts.nstat_txbytes == 0) {
			return EAGAIN;
		}
	}

	result = nstat_accumulate_msg(client, (uint8_t *)buffer, size);
	if (result == 0) {
		src->nts_reported = true;
	}
	return result;
}

static errno_t
nstat_client_send_removed(
	nstat_client    *client,
	nstat_src       *src,
	u_int16_t       hdr_flags)
{
	nstat_msg_src_removed removed;
	errno_t result;

	bzero(&removed, sizeof(removed));
	removed.hdr.type = NSTAT_MSG_TYPE_SRC_REMOVED;
	removed.hdr.length = sizeof(removed);
	removed.hdr.context = 0;
	removed.hdr.flags = hdr_flags;
	removed.srcref = src->nts_srcref;
	result = ctl_enqueuedata(client->ntc_kctl, client->ntc_unit, &removed,
	    sizeof(removed), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		nstat_stats.nstat_msgremovedfailures += 1;
	}

	return result;
}

static errno_t
nstat_client_handle_add_request(
	nstat_client    *client,
	mbuf_t          m)
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

	nstat_provider          *__single provider = NULL;
	nstat_provider_cookie_t __single cookie = NULL;
	nstat_msg_add_src_req *req = mtod(m, nstat_msg_add_src_req *);
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
		uint8_t *req_param_ptr = nstat_get_data(req);
		result = nstat_lookup_entry(req->provider, req_param_ptr, paramlength, &provider, &cookie);
	}

	if (result != 0) {
		return result;
	}

	// sanitize cookie
	nstat_client_sanitize_cookie(client, provider->nstat_provider_id, cookie);

	result = nstat_client_source_add(req->hdr.context, client, provider, cookie, NSTAT_LOCK_NOTHELD);

	if (result != 0) {
		provider->nstat_release(cookie, 0);
	}

	// Set the flag if a provider added a single source
	os_atomic_or(&client->ntc_added_src, (1 << provider->nstat_provider_id), relaxed);

	return result;
}

static errno_t
nstat_set_provider_filter(
	nstat_client            *client,
	nstat_msg_add_all_srcs  *req)
{
	nstat_provider_id_t provider_id = req->provider;

	u_int32_t prev_ntc_watching = os_atomic_or_orig(&client->ntc_watching, (1 << provider_id), relaxed);

	// Reject it if the client is already watching all the sources.
	if ((prev_ntc_watching & (1 << provider_id)) != 0) {
		return EALREADY;
	}

	// Reject it if any single source has already been added.
	u_int32_t ntc_added_src = os_atomic_load(&client->ntc_added_src, relaxed);
	if ((ntc_added_src & (1 << provider_id)) != 0) {
		return EALREADY;
	}

	client->ntc_watching |= (1 << provider_id);
	client->ntc_provider_filters[provider_id].npf_events = req->events;
	client->ntc_provider_filters[provider_id].npf_flags  = req->filter;
	client->ntc_provider_filters[provider_id].npf_pid    = req->target_pid;
	uuid_copy(client->ntc_provider_filters[provider_id].npf_uuid, req->target_uuid);

	// The extensions should be populated by a more direct mechanism
	// Using the top 32 bits of the filter flags reduces the namespace of both,
	// but is a convenient workaround that avoids ntstat.h changes that would require rebuild of all clients
	// Extensions give away additional privacy information and are subject to unconditional privilege check,
	// unconstrained by the value of nstat_privcheck
	if (priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) == 0) {
		client->ntc_provider_filters[provider_id].npf_extensions = (req->filter >> NSTAT_FILTER_ALLOWED_EXTENSIONS_SHIFT) & NSTAT_EXTENDED_UPDATE_FLAG_MASK;
	}
	return 0;
}

static errno_t
nstat_client_handle_add_all(
	nstat_client    *client,
	mbuf_t          m)
{
	errno_t result = 0;

	// Verify the header fits in the first mbuf
	if (mbuf_len(m) < sizeof(nstat_msg_add_all_srcs)) {
		return EINVAL;
	}

	nstat_msg_add_all_srcs *req = mtod(m, nstat_msg_add_all_srcs *);
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

	NSTAT_LOCK_EXCLUSIVE();
	if (req->filter & NSTAT_FILTER_SUPPRESS_SRC_ADDED) {
		// Suppression of source messages implicitly requires the use of update messages
		client->ntc_flags |= NSTAT_FLAG_SUPPORTS_UPDATES;
	}
	NSTAT_UNLOCK_EXCLUSIVE();

	// rdar://problem/30301300   Different providers require different synchronization
	// to ensure that a new entry does not get double counted due to being added prior
	// to all current provider entries being added.  Hence pass the provider the details
	// in the original request for this to be applied atomically

	result = provider->nstat_watcher_add(client, req);

	if (result == 0) {
		nstat_enqueue_success(req->hdr.context, client, 0);
	}

	return result;
}

static errno_t
nstat_client_source_add(
	u_int64_t               context,
	nstat_client            *client,
	nstat_provider          *provider,
	nstat_provider_cookie_t cookie,
	nstat_lock_status lock_status)
{
	if (lock_status == NSTAT_LOCK_NOTHELD) {
		NSTAT_LOCK_EXCLUSIVE();
	} else {
		NSTAT_ASSERT_LOCKED_EXCLUSIVE();
	}

	// Fill out source added message if appropriate
	errno_t result = 0;
	mbuf_ref_t msg = NULL;
	nstat_src_ref_t *srcrefp = NULL;

	u_int64_t provider_filter_flags = client->ntc_provider_filters[provider->nstat_provider_id].npf_flags;
	boolean_t tell_user = ((provider_filter_flags & NSTAT_FILTER_SUPPRESS_SRC_ADDED) == 0);
	u_int32_t src_filter = (provider_filter_flags & NSTAT_FILTER_PROVIDER_NOZEROBYTES)? NSTAT_FILTER_NOZEROBYTES : 0;

	if (provider_filter_flags & NSTAT_FILTER_TCP_NO_EARLY_CLOSE) {
		src_filter |= NSTAT_FILTER_TCP_NO_EARLY_CLOSE;
	}

	do {
		if (tell_user) {
			unsigned int one = 1;

			if (mbuf_allocpacket(MBUF_DONTWAIT, sizeof(nstat_msg_src_added),
			    &one, &msg) != 0) {
				NSTAT_NOTE_QUAL(nstat_src_add_no_buf, client, 0);
				result = ENOMEM;
				break;
			}

			mbuf_setlen(msg, sizeof(nstat_msg_src_added));
			mbuf_pkthdr_setlen(msg, mbuf_len(msg));
			bzero(m_mtod_current(msg), sizeof(nstat_msg_src_added));

			nstat_msg_src_added *add = mtod(msg, nstat_msg_src_added *);
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
			NSTAT_NOTE_QUAL(nstat_src_add_no_src_mem, client, 0);
			if (msg) {
				mbuf_freem(msg);
			}
			result = ENOMEM;
			break;
		}

		// Fill in the source, including picking an unused source ref

		src->nts_srcref = nstat_client_next_src_ref(client);
		if (srcrefp) {
			*srcrefp = src->nts_srcref;
		}

		if (client->ntc_flags & NSTAT_FLAG_CLEANUP || src->nts_srcref == NSTAT_SRC_REF_INVALID) {
			NSTAT_NOTE_QUAL(nstat_src_add_while_cleanup, client, 0);
			kfree_type(struct nstat_src, src);
			if (msg) {
				mbuf_freem(msg);
			}
			result = EINVAL;
			break;
		}
		src->nts_provider = provider;
		src->nts_cookie = cookie;
		src->nts_filter = src_filter;
		src->nts_seq = 0;

		if (msg) {
			// send the source added message if appropriate
			result = ctl_enqueuembuf(client->ntc_kctl, client->ntc_unit, msg, CTL_DATA_EOR);
			if (result != 0) {
				NSTAT_NOTE_SRC(nstat_src_add_send_err, client, src);
				nstat_stats.nstat_srcaddedfailures += 1;
				kfree_type(struct nstat_src, src);
				mbuf_freem(msg);
				break;
			}
		}
		// Put the source in the list
		TAILQ_INSERT_HEAD(&client->ntc_src_queue, src, nts_client_link);
		src->nts_client = client;

		NSTAT_GLOBAL_COUNT_INCREMENT(nstat_global_src_allocs);
		NSTAT_GLOBAL_COUNT_INCREMENT_WITH_MAX(nstat_global_src_current, nstat_global_src_max);

		client->ntc_metrics.nstat_src_current++;
		if (client->ntc_metrics.nstat_src_current > client->ntc_metrics.nstat_src_max) {
			client->ntc_metrics.nstat_src_max = client->ntc_metrics.nstat_src_current;
		}

		NSTAT_NOTE_SRC(nstat_src_add_success, client, src);
	} while (0);

	if (lock_status == NSTAT_LOCK_NOTHELD) {
		NSTAT_UNLOCK_EXCLUSIVE();
	}
	return result;
}

static errno_t
nstat_client_handle_remove_request(
	nstat_client    *client,
	mbuf_t          m)
{
	nstat_src_ref_t srcref = NSTAT_SRC_REF_INVALID;
	nstat_src *src;

	if (mbuf_copydata(m, offsetof(nstat_msg_rem_src_req, srcref), sizeof(srcref), &srcref) != 0) {
		return EINVAL;
	}

	NSTAT_LOCK_EXCLUSIVE();

	// Remove this source as we look for it
	TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
	{
		if (src->nts_srcref == srcref) {
			break;
		}
	}
	if (src) {
		TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
	}

	NSTAT_UNLOCK_EXCLUSIVE();

	if (src) {
		nstat_client_cleanup_source(client, src, FALSE);
		NSTAT_NOTE_QUAL(nstat_remove_src_found, client, srcref);
	} else {
		NSTAT_NOTE_QUAL(nstat_remove_src_missed, client, srcref);
	}

	return src ? 0 : ENOENT;
}

static errno_t
nstat_client_handle_query_request(
	nstat_client    *client,
	mbuf_t          m)
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

	if (all_srcs) {
		NSTAT_NOTE_QUAL(nstat_query_request_all, client, 0);
	} else {
		NSTAT_NOTE_QUAL(nstat_query_request_one, client, req.srcref);
	}

	NSTAT_LOCK_SHARED();

	if (all_srcs) {
		client->ntc_flags |= NSTAT_FLAG_REQCOUNTS;
	}
	nstat_src       *src, *tmpsrc;
	u_int64_t       src_count = 0;
	boolean_t       partial = FALSE;

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_client_begin_query.
	 */
	partial = nstat_client_begin_query(client, &req.hdr);


	TAILQ_FOREACH_SAFE(src, &client->ntc_src_queue, nts_client_link, tmpsrc)
	{
		int     gone = 0;

		// XXX ignore IFACE types?
		if (all_srcs || src->nts_srcref == req.srcref) {
			if (nstat_client_reporting_allowed(client, src, 0)
			    && (!partial || !all_srcs || src->nts_seq != client->ntc_seq)) {
				if (all_srcs) {
					result = nstat_client_append_counts(client, src, &gone);
				} else {
					result = nstat_client_send_counts(client, src, req.hdr.context, 0, &gone);
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
					NSTAT_NOTE_SRC(nstat_query_request_nobuf, client, src);
					client->ntc_flags &= ~NSTAT_FLAG_REQCOUNTS;
					break;
				}
				if (partial) {
					/*
					 * We skip over hard errors and
					 * filtered sources.
					 */
					src->nts_seq = client->ntc_seq;
					src_count++;
				}
			}
		}

		if (gone) {
			// send one last descriptor message so client may see last state
			// If we can't send the notification now, it
			// will be sent in the idle cleanup.
			if (NSTAT_LOCK_SHARED_TO_EXCLUSIVE()) {
				NSTAT_NOTE_SRC(nstat_query_request_upgrade, client, src);
				// Successfully upgraded the lock, now we can remove the source from the client
				result = nstat_client_send_description(client, src, 0, 0);
				if (result != 0) {
					nstat_stats.nstat_control_send_description_failures++;
					if (nstat_debug != 0) {
						NSTAT_LOG_ERROR("nstat_client_send_description() %d", result);
					}
					client->ntc_flags &= ~NSTAT_FLAG_REQCOUNTS;
					NSTAT_NOTE_SRC(nstat_query_request_nodesc, client, src);
					NSTAT_LOCK_EXCLUSIVE_TO_SHARED();
					break;
				}

				// pull src out of the list
				TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
				TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
				NSTAT_LOCK_EXCLUSIVE_TO_SHARED();
			} else {
				// The upgrade failed and the shared lock has been dropped
				// This should be rare.  Simply drop out here and have user level retry
				// the poll, have the idle cleanup catch the "gone" source
				NSTAT_NOTE_SRC(nstat_query_request_noupgrade, client, src);
				NSTAT_LOCK_SHARED();
				break;
			}
		}

		if (all_srcs) {
			if (src_count >= QUERY_CONTINUATION_SRC_COUNT) {
				NSTAT_NOTE_SRC(nstat_query_request_limit, client, src);
				break;
			}
			if ((src_count >= QUERY_CONTINUATION_MIN_SRC_COUNT) &&
			    (NSTAT_LOCK_WOULD_YIELD())) {
				// A possibly higher priority thread is waiting
				// Exit from here and have user level initiate the next fragment
				NSTAT_NOTE_SRC(nstat_query_request_yield, client, src);
				break;
			}
		} else if (req.srcref == src->nts_srcref) {
			break;
		}
	}

	nstat_flush_accumulated_msgs(client);

	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL) {
		flags = nstat_client_end_query(client, src, partial);
	}

	NSTAT_UNLOCK_SHARED();

	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_client_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result) {
		nstat_enqueue_success(req.hdr.context, client, flags);
		result = 0;
	}

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		nstat_client_cleanup_source(client, src, FALSE);
	}

	return result;
}

static errno_t
nstat_client_handle_get_src_description(
	nstat_client    *client,
	mbuf_t          m)
{
	nstat_msg_get_src_description   req;
	errno_t result = ENOENT;
	nstat_src *src;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0) {
		return EINVAL;
	}

	NSTAT_LOCK_SHARED();
	u_int64_t src_count = 0;
	boolean_t partial = FALSE;
	const boolean_t all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);

	if (all_srcs) {
		NSTAT_NOTE_QUAL(nstat_query_description_all, client, 0);
	} else {
		NSTAT_NOTE_QUAL(nstat_query_description_one, client, req.srcref);
	}

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_client_begin_query.
	 */
	partial = nstat_client_begin_query(client, &req.hdr);

	TAILQ_FOREACH(src, &client->ntc_src_queue, nts_client_link)
	{
		if (all_srcs || src->nts_srcref == req.srcref) {
			if (nstat_client_reporting_allowed(client, src, 0)
			    && (!all_srcs || !partial || src->nts_seq != client->ntc_seq)) {
				if (all_srcs) {
					result = nstat_client_append_description(client, src);
				} else {
					result = nstat_client_send_description(client, src, req.hdr.context, 0);
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
					src->nts_seq = client->ntc_seq;
					src_count++;
					if (src_count >= QUERY_CONTINUATION_SRC_COUNT) {
						NSTAT_NOTE_SRC(nstat_query_description_limit, client, src);
						break;
					}
					if ((src_count >= QUERY_CONTINUATION_MIN_SRC_COUNT) &&
					    (NSTAT_LOCK_WOULD_YIELD())) {
						// A possibly higher priority thread is waiting
						// Exit from here and have user level initiate the next fragment
						NSTAT_NOTE_SRC(nstat_query_description_yield, client, src);
						break;
					}
				}
			}

			if (!all_srcs) {
				break;
			}
		}
	}
	nstat_flush_accumulated_msgs(client);

	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL) {
		flags = nstat_client_end_query(client, src, partial);
	}

	NSTAT_UNLOCK_SHARED();
	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_client_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result) {
		nstat_enqueue_success(req.hdr.context, client, flags);
		result = 0;
	}

	return result;
}

static void
nstat_send_error(
	nstat_client *client,
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

	result = ctl_enqueuedata(client->ntc_kctl, client->ntc_unit, &err,
	    sizeof(err), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		nstat_stats.nstat_msgerrorfailures++;
	}
}

static boolean_t
nstat_client_begin_query(
	nstat_client        *client,
	const nstat_msg_hdr *hdrp)
{
	boolean_t partial = FALSE;

	if (hdrp->flags & NSTAT_MSG_HDR_FLAG_CONTINUATION) {
		/* A partial query all has been requested. */
		partial = TRUE;

		if (client->ntc_context != hdrp->context) {
			if (client->ntc_context != 0) {
				nstat_send_error(client, client->ntc_context, EAGAIN);
			}

			/* Initialize client for a partial query all. */
			client->ntc_context = hdrp->context;
			client->ntc_seq++;
		}
	}

	return partial;
}

static u_int16_t
nstat_client_end_query(
	nstat_client *client,
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
		client->ntc_context = 0;
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
nstat_client_handle_get_update(
	nstat_client    *client,
	mbuf_t          m)
{
	nstat_msg_query_src_req req;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0) {
		return EINVAL;
	}

	NSTAT_LOCK_SHARED();

	client->ntc_flags |= NSTAT_FLAG_SUPPORTS_UPDATES;

	errno_t         result = ENOENT;
	nstat_src       *src, *tmpsrc;
	tailq_head_nstat_src dead_list;
	u_int64_t src_count = 0;
	boolean_t partial = FALSE;
	const boolean_t all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);
	TAILQ_INIT(&dead_list);

	if (all_srcs) {
		NSTAT_NOTE_QUAL(nstat_query_update_all, client, 0);
	} else {
		NSTAT_NOTE_QUAL(nstat_query_update_one, client, req.srcref);
	}

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_client_begin_query.
	 */
	partial = nstat_client_begin_query(client, &req.hdr);

	TAILQ_FOREACH_SAFE(src, &client->ntc_src_queue, nts_client_link, tmpsrc) {
		int gone = 0;
		if (all_srcs) {
			// Check to see if we should handle this source or if we're still skipping to find where to continue
			if ((FALSE == partial || src->nts_seq != client->ntc_seq)) {
				u_int64_t suppression_flags = (src->nts_reported)? NSTAT_FILTER_SUPPRESS_BORING_POLL: 0;
				if (nstat_client_reporting_allowed(client, src, suppression_flags)) {
					result = nstat_client_append_update(client, src, &gone);
					if (ENOMEM == result || ENOBUFS == result) {
						/*
						 * If the update message failed to
						 * enqueue then give up.
						 */
						NSTAT_NOTE_SRC(nstat_query_update_nobuf, client, src);
						break;
					}
					if (partial) {
						/*
						 * We skip over hard errors and
						 * filtered sources.
						 */
						src->nts_seq = client->ntc_seq;
						src_count++;
					}
				}
			}
		} else if (src->nts_srcref == req.srcref) {
			if (nstat_client_reporting_allowed(client, src, 0)) {
				result = nstat_client_send_update(client, src, req.hdr.context, 0, 0, &gone);
			}
		}

		if (gone) {
			if (NSTAT_LOCK_SHARED_TO_EXCLUSIVE()) {
				// Successfully upgraded the lock, now we can remove the source from the client
				// pull src out of the list
				TAILQ_REMOVE(&client->ntc_src_queue, src, nts_client_link);
				TAILQ_INSERT_TAIL(&dead_list, src, nts_client_link);
				NSTAT_LOCK_EXCLUSIVE_TO_SHARED();
				NSTAT_NOTE_SRC(nstat_query_update_upgrade, client, src);
			} else {
				// The upgrade failed and the shared lock has been dropped
				// This should be rare.  Simply drop out here and have user level retry
				// the poll, have the idle cleanup catch the "gone" source
				NSTAT_NOTE_SRC(nstat_query_update_noupgrade, client, src);
				NSTAT_LOCK_SHARED();
				break;
			}
		}

		if (!all_srcs && req.srcref == src->nts_srcref) {
			break;
		}
		if (src_count >= QUERY_CONTINUATION_SRC_COUNT) {
			NSTAT_NOTE_SRC(nstat_query_update_limit, client, src);
			break;
		}
		if ((src_count >= QUERY_CONTINUATION_MIN_SRC_COUNT) &&
		    (NSTAT_LOCK_WOULD_YIELD())) {
			// A possibly higher priority thread is waiting
			// Exit from here and have user level initiate the next fragment
			NSTAT_NOTE_SRC(nstat_query_update_yield, client, src);
			break;
		}
	}

	nstat_flush_accumulated_msgs(client);


	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL) {
		flags = nstat_client_end_query(client, src, partial);
	}
	NSTAT_UNLOCK_SHARED();

	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_client_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result) {
		nstat_enqueue_success(req.hdr.context, client, flags);
		result = 0;
	}

	while ((src = TAILQ_FIRST(&dead_list))) {
		TAILQ_REMOVE(&dead_list, src, nts_client_link);
		// release src and send notification
		nstat_client_cleanup_source(client, src, FALSE);
	}

	return result;
}

static errno_t
nstat_client_handle_subscribe_sysinfo(
	nstat_client    *client)
{
	errno_t result = priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);

	if (result != 0) {
		return result;
	}

	NSTAT_LOCK_EXCLUSIVE();
	client->ntc_flags |= NSTAT_FLAG_SYSINFO_SUBSCRIBED;
	NSTAT_UNLOCK_EXCLUSIVE();

	return 0;
}

static errno_t
nstat_client_send(
	kern_ctl_ref    kctl,
	u_int32_t       unit,
	void            *uinfo,
	mbuf_t          m,
	__unused int    flags)
{
	nstat_client     *client = (nstat_client*)uinfo;
	struct nstat_msg_hdr    *hdr;
	struct nstat_msg_hdr    storage;
	errno_t                                 result = 0;

	if (mbuf_pkthdr_len(m) < sizeof(*hdr)) {
		// Is this the right thing to do?
		mbuf_freem(m);
		return EINVAL;
	}

	if (mbuf_len(m) >= sizeof(*hdr)) {
		hdr = mtod(m, struct nstat_msg_hdr *);
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

	lck_mtx_lock(&client->ntc_user_mtx); /* Prevent misbehaving clients from overlapping calls */
	switch (hdr->type) {
	case NSTAT_MSG_TYPE_ADD_SRC:
		result = nstat_client_handle_add_request(client, m);
		break;

	case NSTAT_MSG_TYPE_ADD_ALL_SRCS:
		result = nstat_client_handle_add_all(client, m);
		break;

	case NSTAT_MSG_TYPE_REM_SRC:
		result = nstat_client_handle_remove_request(client, m);
		break;

	case NSTAT_MSG_TYPE_QUERY_SRC:
		result = nstat_client_handle_query_request(client, m);
		break;

	case NSTAT_MSG_TYPE_GET_SRC_DESC:
		result = nstat_client_handle_get_src_description(client, m);
		break;

	case NSTAT_MSG_TYPE_GET_UPDATE:
		result = nstat_client_handle_get_update(client, m);
		break;

	case NSTAT_MSG_TYPE_SUBSCRIBE_SYSINFO:
		result = nstat_client_handle_subscribe_sysinfo(client);
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
	lck_mtx_unlock(&client->ntc_user_mtx);

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

		uint32_t flags = nstat_ifnet_to_flags(ifp);
		if (filter_flags & flags) {
			result = true;
		}
	}
	return result;
}


static int
progress_indicators_for_interface(unsigned int ifindex, uint64_t recentflow_maxduration, uint32_t filter_flags, uint64_t transport_protocol_mask, struct nstat_progress_indicators *indicators)
{
	int error = 0;
	struct inpcb *inp;
	uint64_t min_recent_start_time;
	bool update_tcp_indicators = ((transport_protocol_mask & PR_PROTO_TCP) == PR_PROTO_TCP) || (transport_protocol_mask == 0);
	bool update_quic_indicators = (transport_protocol_mask & PR_PROTO_QUIC) == PR_PROTO_QUIC;
#if SKYWALK
	struct nstat_tu_shadow *shad;
#endif /* SKYWALK */

	min_recent_start_time = mach_continuous_time() - recentflow_maxduration;
	bzero(indicators, sizeof(*indicators));

	if (nstat_debug != 0) {
		/* interface index -1 may be passed in to only match against the filters specified in the flags */
		if (ifindex < UINT_MAX) {
			NSTAT_LOG_DEBUG("for interface index %u with flags %x", ifindex, filter_flags);
		} else {
			NSTAT_LOG_DEBUG("for matching interface with flags %x", filter_flags);
		}
	}

	if (update_tcp_indicators) {
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
			if (tp && inp->inp_state != INPCB_STATE_DEAD && inp->inp_last_outifp &&
			    /* matches the given interface index, or against any provided filter flags */
			    (((inp->inp_last_outifp->if_index == ifindex) ||
			    nstat_interface_matches_filter_flag(filter_flags, inp->inp_last_outifp)) &&
			    /* perform flow state matching based any provided filter flags */
			    (((filter_flags & (NSTAT_IFNET_IS_NON_LOCAL | NSTAT_IFNET_IS_LOCAL)) == 0) ||
			    ((filter_flags & NSTAT_IFNET_IS_NON_LOCAL) && !(tp->t_flags & TF_LOCAL)) ||
			    ((filter_flags & NSTAT_IFNET_IS_LOCAL) && (tp->t_flags & TF_LOCAL))))) {
				struct tcp_conn_status connstatus;

				if (nstat_debug != 0) {
					NSTAT_LOG_DEBUG("*matched non-Skywalk* [filter match: %d]", nstat_interface_matches_filter_flag(filter_flags, inp->inp_last_outifp));
				}

				indicators->np_numflows++;
				tcp_get_connectivity_status(tp, &connstatus);
				if (connstatus.write_probe_failed) {
					indicators->np_write_probe_fails++;
				}
				if (connstatus.read_probe_failed) {
					indicators->np_read_probe_fails++;
				}
				if (connstatus.conn_probe_failed) {
					indicators->np_conn_probe_fails++;
				}
				if (inp->inp_start_timestamp > min_recent_start_time) {
					uint64_t flow_count;

					indicators->np_recentflows++;
					flow_count = os_atomic_load(&inp->inp_stat->rxbytes, relaxed);
					indicators->np_recentflows_rxbytes += flow_count;
					flow_count = os_atomic_load(&inp->inp_stat->txbytes, relaxed);
					indicators->np_recentflows_txbytes += flow_count;

					indicators->np_recentflows_rxooo += tp->t_stat.rxoutoforderbytes;
					indicators->np_recentflows_rxdup += tp->t_stat.rxduplicatebytes;
					indicators->np_recentflows_retx += tp->t_stat.txretransmitbytes;
					if (tp->snd_max - tp->snd_una) {
						indicators->np_recentflows_unacked++;
					}
				}
			}
		}
		lck_rw_done(&tcbinfo.ipi_lock);
	}

#if SKYWALK
	u_int32_t locality_flags = (filter_flags & (NSTAT_IFNET_IS_LOCAL | NSTAT_IFNET_IS_NON_LOCAL));
	u_int32_t flag_mask = (NSTAT_FILTER_IFNET_FLAGS & ~(NSTAT_IFNET_IS_NON_LOCAL | NSTAT_IFNET_IS_LOCAL));
	u_int32_t interface_flags = (filter_flags & flag_mask);

	NSTAT_LOCK_SHARED();

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		bool consider_shad = false;
		if (shad->shad_live) {
			if (shad->shad_provider == NSTAT_PROVIDER_QUIC_USERLAND) {
				consider_shad = update_quic_indicators;
			} else if (shad->shad_provider == NSTAT_PROVIDER_TCP_USERLAND) {
				consider_shad = update_tcp_indicators;
			}
		}

		if (consider_shad) {
			u_int32_t ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
			nstat_progress_digest digest;
			bzero(&digest, sizeof(digest));

			// fetch ifflags and digest from necp_client
			bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, &ifflags, &digest, NULL, NULL);
			error = (result)? 0 : EIO;
			if (error) {
				NSTAT_LOG_ERROR("nstat get ifflags and progressdigest returned %d", error);
				continue;
			}
			if (ifflags & (NSTAT_IFNET_FLOWSWITCH_VALUE_UNOBTAINABLE | NSTAT_IFNET_ROUTE_VALUE_UNOBTAINABLE)) {
				NSTAT_LOG_ERROR("nstat get ifflags and progressdigest resulted in Skywalk error, ifflags=%x", ifflags);
				continue;
			}

			if ((digest.ifindex == (u_int32_t)ifindex) ||
			    ((ifindex == UINT_MAX) && ((ifflags & interface_flags) != 0))) {
				// a match on either a requested interface index or on interface type
				if ((locality_flags != 0) && ((locality_flags & ifflags) == 0)) {
					continue;
				}

				if (nstat_debug != 0) {
					NSTAT_LOG_DEBUG("*matched Skywalk* [ifindex=%u digest.ifindex=%u filter_flags=%x ifflags=%x]", ifindex, digest.ifindex, filter_flags, ifflags);
				}

				indicators->np_numflows++;
				if (digest.connstatus.write_probe_failed) {
					indicators->np_write_probe_fails++;
				}
				if (digest.connstatus.read_probe_failed) {
					indicators->np_read_probe_fails++;
				}
				if (digest.connstatus.conn_probe_failed) {
					indicators->np_conn_probe_fails++;
				}
				if (shad->shad_start_timestamp > min_recent_start_time) {
					indicators->np_recentflows++;
					indicators->np_recentflows_rxbytes += digest.rxbytes;
					indicators->np_recentflows_txbytes += digest.txbytes;
					indicators->np_recentflows_rxooo += digest.rxoutoforderbytes;
					indicators->np_recentflows_rxdup += digest.rxduplicatebytes;
					indicators->np_recentflows_retx += digest.txretransmit;
					if (digest.txunacked) {
						indicators->np_recentflows_unacked++;
					}
				}
			}
		}
	}

	NSTAT_UNLOCK_SHARED();

#endif /* SKYWALK */
	return error;
}


static int
tcp_progress_probe_enable_for_interface(unsigned int ifindex, uint32_t filter_flags, uint32_t enable_flags)
{
	int error = 0;
	struct ifnet *ifp;

	if (nstat_debug != 0) {
		NSTAT_LOG_DEBUG("for interface index %u with flags %d", ifindex, filter_flags);
	}

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
	{
		if ((ifp->if_index == ifindex) ||
		    nstat_interface_matches_filter_flag(filter_flags, ifp)) {
			if (nstat_debug != 0) {
				NSTAT_LOG_DEBUG("*matched* interface index %d, enable: %d", ifp->if_index, enable_flags);
			}
			error = if_probe_connectivity(ifp, enable_flags);
			if (error) {
				NSTAT_LOG_ERROR("(%d) - nstat set tcp probe %d for interface index %d", error, enable_flags, ifp->if_index);
			}
		}
	}
	ifnet_head_done();

	return error;
}


static int
ntstat_progress_indicators(struct sysctl_req *req)
{
	struct nstat_progress_indicators indicators = {};
	int error = 0;
	struct nstat_progress_req requested;

	if (priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) != 0) {
		return EACCES;
	}
	if (req->newptr == USER_ADDR_NULL) {
		return EINVAL;
	}
	if (req->newlen < sizeof(requested)) {
		return EINVAL;
	}
	error = SYSCTL_IN(req, &requested, sizeof(requested));
	if (error != 0) {
		return error;
	}
	error = progress_indicators_for_interface((unsigned int)requested.np_ifindex, requested.np_recentflow_maxduration, (uint32_t)requested.np_filter_flags, requested.np_transport_protocol_mask, &indicators);
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
	if (req->newlen < sizeof(requested)) {
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

static int
nstat_gather_flow_data(nstat_provider_id_t provider, nstat_flow_data *__counted_by(n)flow_data_start, int n)
{
	nstat_flow_data * flow_data = flow_data_start;
	struct nstat_tu_shadow *shad;
	int prepared = 0;
	errno_t err;

	NSTAT_ASSERT_LOCKED();

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if ((shad->shad_provider == provider) && (shad->shad_live)) {
			if (prepared >= n) {
				break;
			}
			err = nstat_userland_tu_copy_descriptor((nstat_provider_cookie_t) shad,
			    &flow_data->flow_descriptor, sizeof(flow_data->flow_descriptor));

			if (err != 0) {
				NSTAT_LOG_ERROR("nstat_userland_tu_copy_descriptor  returned %d", err);
			}
			err = nstat_userland_tu_counts((nstat_provider_cookie_t) shad,
			    &flow_data->counts, NULL);
			if (err != 0) {
				NSTAT_LOG_ERROR("nstat_userland_tu_counts  returned %d", err);
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
nstat_userland_get_snapshot(short proto, void *__sized_by(*snapshot_size) * snapshotp, size_t *snapshot_size, int *countp)
{
	int error = 0;
	int n = 0;
	size_t data_size = 0;
	nstat_provider_id_t provider;
	nstat_flow_data *flow_data = NULL;

	NSTAT_LOCK_SHARED();
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

	data_size = n * sizeof(*flow_data);
	flow_data = (nstat_flow_data *) kalloc_data(data_size,
	    Z_WAITOK | Z_ZERO);
	if (flow_data) {
		n = nstat_gather_flow_data(provider, flow_data, n);
	} else {
		error = ENOMEM;
	}
done:
	NSTAT_UNLOCK_SHARED();
	*snapshotp = flow_data;
	*snapshot_size = data_size;
	*countp = n;
	return error;
}

// nstat_userland_list_snapshot() does most of the work for a sysctl that uses a return format
// as per get_pcblist_n() even though the vast majority of fields are unused.
// Additional items are required in the sysctl output before and after the data added
// by this function.
__private_extern__ int
nstat_userland_list_snapshot(short proto, struct sysctl_req *req, void *__sized_by(n * sizeof(nstat_flow_data))userlandsnapshot, int n)
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
