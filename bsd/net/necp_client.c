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

#include <string.h>

#include <kern/thread_call.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/net_api_stats.h>
#include <net/necp.h>
#include <net/network_agent.h>
#include <net/ntstat.h>

#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/mp_pcb.h>
#include <netinet/tcp_cc.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_cache.h>
#include <netinet6/in6_var.h>

#include <sys/domain.h>
#include <sys/file_internal.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/codesign.h>
#include <libkern/section_keywords.h>

#include <os/refcnt.h>

#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#endif /* SKYWALK */

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/*
 * NECP Client Architecture
 * ------------------------------------------------
 * See <net/necp.c> for a discussion on NECP database architecture.
 *
 * Each client of NECP provides a set of parameters for a connection or network state
 * evaluation, on which NECP policy evaluation is run. This produces a policy result
 * which can be accessed by the originating process, along with events for when policies
 * results have changed.
 *
 * ------------------------------------------------
 * NECP Client FD
 * ------------------------------------------------
 * A process opens an NECP file descriptor using necp_open(). This is a very simple
 * file descriptor, upon which the process may do the following operations:
 *   - necp_client_action(...), to add/remove/query clients
 *   - kqueue, to watch for readable events
 *   - close(), to close the client session and release all clients
 *
 * Client objects are allocated structures that hang off of the file descriptor. Each
 * client contains:
 *   - Client ID, a UUID that references the client across the system
 *   - Parameters, a buffer of TLVs that describe the client's connection parameters,
 *       such as the remote and local endpoints, interface requirements, etc.
 *   - Result, a buffer of TLVs containing the current policy evaluation for the client.
 *       This result will be updated whenever a network change occurs that impacts the
 *       policy result for that client.
 *
 *                   +--------------+
 *                   |   NECP fd    |
 *                   +--------------+
 *                          ||
 *          ==================================
 *          ||              ||              ||
 *  +--------------+ +--------------+ +--------------+
 *  |   Client ID  | |   Client ID  | |   Client ID  |
 *  |     ----     | |     ----     | |     ----     |
 *  |  Parameters  | |  Parameters  | |  Parameters  |
 *  |     ----     | |     ----     | |     ----     |
 *  |    Result    | |    Result    | |    Result    |
 *  +--------------+ +--------------+ +--------------+
 *
 * ------------------------------------------------
 * Client Actions
 * ------------------------------------------------
 *   - Add. Input parameters as a buffer of TLVs, and output a client ID. Allocates a
 *       new client structure on the file descriptor.
 *   - Remove. Input a client ID. Removes a client structure from the file descriptor.
 *   - Copy Parameters. Input a client ID, and output parameter TLVs.
 *   - Copy Result. Input a client ID, and output result TLVs. Alternatively, input empty
 *       client ID and get next unread client result.
 *   - Copy List. List all client IDs.
 *
 * ------------------------------------------------
 * Client Policy Evaluation
 * ------------------------------------------------
 * Policies are evaluated for clients upon client creation, and upon update events,
 * which are network/agent/policy changes coalesced by a timer.
 *
 * The policy evaluation goes through the following steps:
 *   1. Parse client parameters.
 *   2. Select a scoped interface if applicable. This involves using require/prohibit
 *      parameters, along with the local address, to select the most appropriate interface
 *      if not explicitly set by the client parameters.
 *   3. Run NECP application-level policy evalution
 *   4. Set policy result into client result buffer.
 *
 * ------------------------------------------------
 * Client Observers
 * ------------------------------------------------
 * If necp_open() is called with the NECP_OPEN_FLAG_OBSERVER flag, and the process
 * passes the necessary privilege check, the fd is allowed to use necp_client_action()
 * to copy client state attached to the file descriptors of other processes, and to
 * list all client IDs on the system.
 */

extern u_int32_t necp_debug;

static int necpop_select(struct fileproc *, int, void *, vfs_context_t);
static int necpop_close(struct fileglob *, vfs_context_t);
static int necpop_kqfilter(struct fileproc *, struct knote *, struct kevent_qos_s *);

// Timer functions
static int necp_timeout_microseconds = 1000 * 100; // 100ms
static int necp_timeout_leeway_microseconds = 1000 * 500; // 500ms
#if SKYWALK
static int necp_collect_stats_timeout_microseconds = 1000 * 1000 * 1; // 1s
static int necp_collect_stats_timeout_leeway_microseconds = 1000 * 500; // 500ms
static int necp_close_arenas_timeout_microseconds = 1000 * 1000 * 10; // 10s
static int necp_close_arenas_timeout_leeway_microseconds = 1000 * 1000 * 1; // 1s
#endif /* SKYWALK */

static int necp_client_fd_count = 0;
static int necp_observer_fd_count = 0;
static int necp_client_count = 0;
static int necp_socket_flow_count = 0;
static int necp_if_flow_count = 0;
static int necp_observer_message_limit = 256;

/*
 * NECP client tracing control -
 *
 * necp_client_tracing_level  : 1 for client trace, 2 for flow trace, 3 for parameter details
 * necp_client_tracing_pid    : match client with pid
 */
static int necp_client_tracing_level = 0;
static int necp_client_tracing_pid = 0;

#define NECP_CLIENT_TRACE_LEVEL_CLIENT   1
#define NECP_CLIENT_TRACE_LEVEL_FLOW     2
#define NECP_CLIENT_TRACE_LEVEL_PARAMS   3

#define NECP_CLIENT_TRACE_PID_MATCHED(pid) \
    (pid == necp_client_tracing_pid)

#define NECP_ENABLE_CLIENT_TRACE(level) \
    ((necp_client_tracing_level >= level && \
      (!necp_client_tracing_pid || NECP_CLIENT_TRACE_PID_MATCHED(client->proc_pid))) ? necp_client_tracing_level : 0)

#define NECP_CLIENT_LOG(client, fmt, ...)                                                                       \
    if (client && NECP_ENABLE_CLIENT_TRACE(NECP_CLIENT_TRACE_LEVEL_CLIENT)) {                                   \
	uuid_string_t client_uuid_str = { };                                                                        \
	uuid_unparse_lower(client->client_id, client_uuid_str);                                                     \
	NECPLOG(LOG_NOTICE, "NECP_CLIENT_LOG <pid %d %s>: " fmt "\n", client ? client->proc_pid : 0, client_uuid_str, ##__VA_ARGS__); \
    }

#define NECP_CLIENT_FLOW_LOG(client, flow, fmt, ...)                                                            \
    if (client && flow && NECP_ENABLE_CLIENT_TRACE(NECP_CLIENT_TRACE_LEVEL_FLOW)) {                             \
	uuid_string_t client_uuid_str = { };                                                                        \
	uuid_unparse_lower(client->client_id, client_uuid_str);                                                     \
	uuid_string_t flow_uuid_str = { };                                                                          \
	uuid_unparse_lower(flow->registration_id, flow_uuid_str);                                                   \
	NECPLOG(LOG_NOTICE, "NECP CLIENT FLOW TRACE <pid %d %s> <flow %s>: " fmt "\n", client ? client->proc_pid : 0, client_uuid_str, flow_uuid_str, ##__VA_ARGS__); \
    }

#define NECP_CLIENT_PARAMS_LOG(client, fmt, ...)                                                                \
    if (client && NECP_ENABLE_CLIENT_TRACE(NECP_CLIENT_TRACE_LEVEL_PARAMS)) {                                   \
    uuid_string_t client_uuid_str = { };                                                                        \
    uuid_unparse_lower(client->client_id, client_uuid_str);                                                     \
    NECPLOG(LOG_NOTICE, "NECP_CLIENT_PARAMS_LOG <pid %d %s>: " fmt "\n", client ? client->proc_pid : 0, client_uuid_str, ##__VA_ARGS__); \
    }

#define NECP_SOCKET_PID(so) \
    ((so->so_flags & SOF_DELEGATED) ? so->e_pid : so->last_pid)

#define NECP_ENABLE_SOCKET_TRACE(level) \
    ((necp_client_tracing_level >= level && \
      (!necp_client_tracing_pid || NECP_CLIENT_TRACE_PID_MATCHED(NECP_SOCKET_PID(so)))) ? necp_client_tracing_level : 0)

#define NECP_SOCKET_PARAMS_LOG(so, fmt, ...)                                                                    \
    if (so && NECP_ENABLE_SOCKET_TRACE(NECP_CLIENT_TRACE_LEVEL_PARAMS)) {                                       \
    NECPLOG(LOG_NOTICE, "NECP_SOCKET_PARAMS_LOG <pid %d>: " fmt "\n", NECP_SOCKET_PID(so), ##__VA_ARGS__);      \
    }

#define NECP_SOCKET_ATTRIBUTE_LOG(fmt, ...)                                                                     \
    if (necp_client_tracing_level >= NECP_CLIENT_TRACE_LEVEL_PARAMS) {                                          \
    NECPLOG(LOG_NOTICE, "NECP_SOCKET_ATTRIBUTE_LOG: " fmt "\n", ##__VA_ARGS__);                                 \
    }

#define NECP_CLIENT_TRACKER_LOG(pid, fmt, ...)                                                                  \
    if (pid) {                                                                                                  \
    NECPLOG(LOG_NOTICE, "NECP_CLIENT_TRACKER_LOG <pid %d>: " fmt "\n", pid, ##__VA_ARGS__);                     \
    }

#if SKYWALK
static int necp_arena_count = 0;
static int necp_sysctl_arena_count = 0;
static int necp_nexus_flow_count = 0;

/* userspace stats sanity check range, same unit as TCP (see TCP_RTT_SCALE) */
static uint32_t necp_client_stats_rtt_floor = 1; // 32us
static uint32_t necp_client_stats_rtt_ceiling = 1920000; // 60s
const static struct sk_stats_flow ntstat_sk_stats_zero;
#endif /* SKYWALK */

os_refgrp_decl(static, necp_client_refgrp, "NECPClientRefGroup", NULL);

SYSCTL_INT(_net_necp, NECPCTL_CLIENT_FD_COUNT, client_fd_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_client_fd_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_OBSERVER_FD_COUNT, observer_fd_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_observer_fd_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_CLIENT_COUNT, client_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_client_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_SOCKET_FLOW_COUNT, socket_flow_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_socket_flow_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_IF_FLOW_COUNT, if_flow_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_if_flow_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_OBSERVER_MESSAGE_LIMIT, observer_message_limit, CTLFLAG_LOCKED | CTLFLAG_RW, &necp_observer_message_limit, 256, "");
SYSCTL_INT(_net_necp, NECPCTL_CLIENT_TRACING_LEVEL, necp_client_tracing_level, CTLFLAG_LOCKED | CTLFLAG_RW, &necp_client_tracing_level, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_CLIENT_TRACING_PID, necp_client_tracing_pid, CTLFLAG_LOCKED | CTLFLAG_RW, &necp_client_tracing_pid, 0, "");

#if SKYWALK
SYSCTL_INT(_net_necp, NECPCTL_ARENA_COUNT, arena_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_arena_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_SYSCTL_ARENA_COUNT, sysctl_arena_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_sysctl_arena_count, 0, "");
SYSCTL_INT(_net_necp, NECPCTL_NEXUS_FLOW_COUNT, nexus_flow_count, CTLFLAG_LOCKED | CTLFLAG_RD, &necp_nexus_flow_count, 0, "");
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_net_necp, OID_AUTO, collect_stats_interval_us, CTLFLAG_RW | CTLFLAG_LOCKED, &necp_collect_stats_timeout_microseconds, 0, "");
SYSCTL_UINT(_net_necp, OID_AUTO, necp_client_stats_rtt_floor, CTLFLAG_RW | CTLFLAG_LOCKED, &necp_client_stats_rtt_floor, 0, "");
SYSCTL_UINT(_net_necp, OID_AUTO, necp_client_stats_rtt_ceiling, CTLFLAG_RW | CTLFLAG_LOCKED, &necp_client_stats_rtt_ceiling, 0, "");
#endif /* (DEVELOPMENT || DEBUG) */
#endif /* SKYWALK */

#define NECP_MAX_CLIENT_LIST_SIZE               1024 * 1024 // 1MB
#define NECP_MAX_AGENT_ACTION_SIZE              256

extern int tvtohz(struct timeval *);
extern unsigned int get_maxmtu(struct rtentry *);

// Parsed parameters
#define NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR                         0x00001
#define NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR                        0x00002
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF                        0x00004
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF                      0x00008
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE            0x00010
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE          0x00020
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT                     0x00040
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT           0x00080
#define NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT            0x00100
#define NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT                      0x00200
#define NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE        0x00400
#define NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE      0x00800
#define NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE       0x01000
#define NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE         0x02000
#define NECP_PARSED_PARAMETERS_FIELD_FLAGS                                      0x04000
#define NECP_PARSED_PARAMETERS_FIELD_IP_PROTOCOL                        0x08000
#define NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID                      0x10000
#define NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_UUID                     0x20000
#define NECP_PARSED_PARAMETERS_FIELD_TRAFFIC_CLASS                      0x40000
#define NECP_PARSED_PARAMETERS_FIELD_LOCAL_PORT                         0x80000
#define NECP_PARSED_PARAMETERS_FIELD_DELEGATED_UPID                     0x100000
#define NECP_PARSED_PARAMETERS_FIELD_ETHERTYPE                          0x200000
#define NECP_PARSED_PARAMETERS_FIELD_TRANSPORT_PROTOCOL                 0x400000
#define NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR_PREFERENCE              0x800000
#define NECP_PARSED_PARAMETERS_FIELD_ATTRIBUTED_BUNDLE_IDENTIFIER       0x1000000
#define NECP_PARSED_PARAMETERS_FIELD_PARENT_UUID                        0x2000000


#define NECP_MAX_INTERFACE_PARAMETERS 16
#define NECP_MAX_AGENT_PARAMETERS 4
struct necp_client_parsed_parameters {
	u_int32_t valid_fields;
	u_int32_t flags;
	u_int64_t delegated_upid;
	union necp_sockaddr_union local_addr;
	union necp_sockaddr_union remote_addr;
	u_int32_t required_interface_index;
	char prohibited_interfaces[NECP_MAX_INTERFACE_PARAMETERS][IFXNAMSIZ];
	u_int8_t required_interface_type;
	u_int8_t local_address_preference;
	u_int8_t prohibited_interface_types[NECP_MAX_INTERFACE_PARAMETERS];
	struct necp_client_parameter_netagent_type required_netagent_types[NECP_MAX_AGENT_PARAMETERS];
	struct necp_client_parameter_netagent_type prohibited_netagent_types[NECP_MAX_AGENT_PARAMETERS];
	struct necp_client_parameter_netagent_type preferred_netagent_types[NECP_MAX_AGENT_PARAMETERS];
	struct necp_client_parameter_netagent_type avoided_netagent_types[NECP_MAX_AGENT_PARAMETERS];
	uuid_t required_netagents[NECP_MAX_AGENT_PARAMETERS];
	uuid_t prohibited_netagents[NECP_MAX_AGENT_PARAMETERS];
	uuid_t preferred_netagents[NECP_MAX_AGENT_PARAMETERS];
	uuid_t avoided_netagents[NECP_MAX_AGENT_PARAMETERS];
	u_int8_t ip_protocol;
	u_int8_t transport_protocol;
	u_int16_t ethertype;
	pid_t effective_pid;
	uuid_t effective_uuid;
	uuid_t parent_uuid;
	u_int32_t traffic_class;
};

static bool
necp_find_matching_interface_index(struct necp_client_parsed_parameters *parsed_parameters,
    u_int *return_ifindex, bool *validate_agents);

static bool
necp_ifnet_matches_local_address(struct ifnet *ifp, struct sockaddr *sa);

static bool
necp_ifnet_matches_parameters(struct ifnet *ifp,
    struct necp_client_parsed_parameters *parsed_parameters,
    u_int32_t override_flags,
    u_int32_t *preferred_count,
    bool secondary_interface,
    bool require_scoped_field);

static const struct fileops necp_fd_ops = {
	.fo_type     = DTYPE_NETPOLICY,
	.fo_read     = fo_no_read,
	.fo_write    = fo_no_write,
	.fo_ioctl    = fo_no_ioctl,
	.fo_select   = necpop_select,
	.fo_close    = necpop_close,
	.fo_drain    = fo_no_drain,
	.fo_kqfilter = necpop_kqfilter,
};

struct necp_client_assertion {
	LIST_ENTRY(necp_client_assertion) assertion_chain;
	uuid_t asserted_netagent;
};

struct necp_client_flow_header {
	struct necp_tlv_header outer_header;
	struct necp_tlv_header flow_id_tlv_header;
	uuid_t flow_id;
	struct necp_tlv_header flags_tlv_header;
	u_int32_t flags_value;
	struct necp_tlv_header interface_tlv_header;
	struct necp_client_result_interface interface_value;
} __attribute__((__packed__));

struct necp_client_flow_protoctl_event_header {
	struct necp_tlv_header protoctl_tlv_header;
	struct necp_client_flow_protoctl_event protoctl_event;
} __attribute__((__packed__));

struct necp_client_nexus_flow_header {
	struct necp_client_flow_header flow_header;
	struct necp_tlv_header agent_tlv_header;
	struct necp_client_result_netagent agent_value;
	struct necp_tlv_header tfo_cookie_tlv_header;
	u_int8_t tfo_cookie_value[NECP_TFO_COOKIE_LEN_MAX];
} __attribute__((__packed__));

#if SKYWALK
struct necp_arena_info;
#endif

struct necp_client_flow {
	LIST_ENTRY(necp_client_flow) flow_chain;
	unsigned invalid : 1;
	unsigned nexus : 1; // If true, flow is a nexus; if false, flow is attached to socket
	unsigned socket : 1;
	unsigned viable : 1;
	unsigned assigned : 1;
	unsigned has_protoctl_event : 1;
	unsigned check_tcp_heuristics : 1;
	unsigned _reserved : 1;
	union {
		uuid_t nexus_agent;
		struct {
			void *socket_handle;
			necp_client_flow_cb cb;
		};
	} u;
	uint32_t interface_index;
	u_short  delegated_interface_index;
	uint16_t interface_flags;
	uint32_t necp_flow_flags;
	struct necp_client_flow_protoctl_event protoctl_event;
	union necp_sockaddr_union local_addr;
	union necp_sockaddr_union remote_addr;

	size_t assigned_results_length;
	u_int8_t *assigned_results;
};

struct necp_client_flow_registration {
	RB_ENTRY(necp_client_flow_registration) fd_link;
	RB_ENTRY(necp_client_flow_registration) global_link;
	RB_ENTRY(necp_client_flow_registration) client_link;
	LIST_ENTRY(necp_client_flow_registration) collect_stats_chain;
	uuid_t registration_id;
	u_int32_t flags;
	unsigned flow_result_read : 1;
	unsigned defunct : 1;
	void *interface_handle;
	necp_client_flow_cb interface_cb;
	struct necp_client *client;
	LIST_HEAD(_necp_registration_flow_list, necp_client_flow) flow_list;
#if SKYWALK
	struct necp_arena_info *stats_arena;    /* arena where the stats objects came from */
	void * kstats_kaddr;    /* kernel snapshot of untrusted userspace stats, for calculating delta */
	mach_vm_address_t ustats_uaddr; /* userspace stats (untrusted) */
	nstat_userland_context stats_handler_context;
	struct flow_stats *nexus_stats; /* shared stats objects between necp_client and skywalk */
#endif /* !SKYWALK */
	u_int64_t last_interface_details __attribute__((aligned(sizeof(u_int64_t))));
};

static int necp_client_flow_id_cmp(struct necp_client_flow_registration *flow0, struct necp_client_flow_registration *flow1);

RB_HEAD(_necp_client_flow_tree, necp_client_flow_registration);
RB_PROTOTYPE_PREV(_necp_client_flow_tree, necp_client_flow_registration, client_link, necp_client_flow_id_cmp);
RB_GENERATE_PREV(_necp_client_flow_tree, necp_client_flow_registration, client_link, necp_client_flow_id_cmp);

#define NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT 4
#define NECP_CLIENT_MAX_INTERFACE_OPTIONS 16

#define NECP_CLIENT_INTERFACE_OPTION_EXTRA_COUNT (NECP_CLIENT_MAX_INTERFACE_OPTIONS - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT)

struct necp_client {
	RB_ENTRY(necp_client) link;
	RB_ENTRY(necp_client) global_link;

	decl_lck_mtx_data(, lock);
	decl_lck_mtx_data(, route_lock);
	os_refcnt_t reference_count;

	uuid_t client_id;
	unsigned result_read : 1;
	unsigned group_members_read : 1;
	unsigned allow_multiple_flows : 1;
	unsigned legacy_client_is_flow : 1;

	unsigned platform_binary : 1;

	size_t result_length;
	u_int8_t result[NECP_MAX_CLIENT_RESULT_SIZE];

	necp_policy_id policy_id;

	u_int8_t ip_protocol;
	int proc_pid;

	u_int64_t delegated_upid;

	struct _necp_client_flow_tree flow_registrations;
	LIST_HEAD(_necp_client_assertion_list, necp_client_assertion) assertion_list;

	size_t assigned_group_members_length;
	u_int8_t *assigned_group_members;

	struct rtentry *current_route;

	struct necp_client_interface_option interface_options[NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
	struct necp_client_interface_option *extra_interface_options;
	u_int8_t interface_option_count; // Number in interface_options + extra_interface_options

	struct necp_client_result_netagent failed_trigger_agent;

	void *agent_handle;

	uuid_t override_euuid;

#if SKYWALK
	netns_token port_reservation;
	nstat_context nstat_context;
	uuid_t latest_flow_registration_id;
	struct necp_client *original_parameters_source;
#endif /* !SKYWALK */

	size_t parameters_length;
	u_int8_t *parameters;
};

#define NECP_CLIENT_LOCK(_c) lck_mtx_lock(&_c->lock)
#define NECP_CLIENT_UNLOCK(_c) lck_mtx_unlock(&_c->lock)
#define NECP_CLIENT_ASSERT_LOCKED(_c) LCK_MTX_ASSERT(&_c->lock, LCK_MTX_ASSERT_OWNED)
#define NECP_CLIENT_ASSERT_UNLOCKED(_c) LCK_MTX_ASSERT(&_c->lock, LCK_MTX_ASSERT_NOTOWNED)

#define NECP_CLIENT_ROUTE_LOCK(_c) lck_mtx_lock(&_c->route_lock)
#define NECP_CLIENT_ROUTE_UNLOCK(_c) lck_mtx_unlock(&_c->route_lock)

static void necp_client_retain_locked(struct necp_client *client);
static void necp_client_retain(struct necp_client *client);

static bool necp_client_release_locked(struct necp_client *client);
static bool necp_client_release(struct necp_client *client);

static void
necp_client_add_assertion(struct necp_client *client, uuid_t netagent_uuid);

static bool
necp_client_remove_assertion(struct necp_client *client, uuid_t netagent_uuid);

LIST_HEAD(_necp_flow_registration_list, necp_client_flow_registration);
static struct _necp_flow_registration_list necp_collect_stats_flow_list;

struct necp_flow_defunct {
	LIST_ENTRY(necp_flow_defunct) chain;

	uuid_t flow_id;
	uuid_t nexus_agent;
	void *agent_handle;
	int proc_pid;
	u_int32_t flags;
	struct necp_client_agent_parameters close_parameters;
	bool has_close_parameters;
};

LIST_HEAD(_necp_flow_defunct_list, necp_flow_defunct);

static int necp_client_id_cmp(struct necp_client *client0, struct necp_client *client1);

RB_HEAD(_necp_client_tree, necp_client);
RB_PROTOTYPE_PREV(_necp_client_tree, necp_client, link, necp_client_id_cmp);
RB_GENERATE_PREV(_necp_client_tree, necp_client, link, necp_client_id_cmp);

RB_HEAD(_necp_client_global_tree, necp_client);
RB_PROTOTYPE_PREV(_necp_client_global_tree, necp_client, global_link, necp_client_id_cmp);
RB_GENERATE_PREV(_necp_client_global_tree, necp_client, global_link, necp_client_id_cmp);

RB_HEAD(_necp_fd_flow_tree, necp_client_flow_registration);
RB_PROTOTYPE_PREV(_necp_fd_flow_tree, necp_client_flow_registration, fd_link, necp_client_flow_id_cmp);
RB_GENERATE_PREV(_necp_fd_flow_tree, necp_client_flow_registration, fd_link, necp_client_flow_id_cmp);

RB_HEAD(_necp_client_flow_global_tree, necp_client_flow_registration);
RB_PROTOTYPE_PREV(_necp_client_flow_global_tree, necp_client_flow_registration, global_link, necp_client_flow_id_cmp);
RB_GENERATE_PREV(_necp_client_flow_global_tree, necp_client_flow_registration, global_link, necp_client_flow_id_cmp);

static struct _necp_client_global_tree necp_client_global_tree;
static struct _necp_client_flow_global_tree necp_client_flow_global_tree;

struct necp_client_update {
	TAILQ_ENTRY(necp_client_update) chain;

	uuid_t client_id;

	size_t update_length;
	struct necp_client_observer_update *update;
};

#if SKYWALK
struct necp_arena_info {
	LIST_ENTRY(necp_arena_info) nai_chain;
	u_int32_t nai_flags;
	pid_t nai_proc_pid;
	struct skmem_arena *nai_arena;
	struct skmem_arena_mmap_info nai_mmap;
	mach_vm_offset_t nai_roff;
	u_int32_t nai_use_count;
};
#endif /* !SKYWALK */

#define NAIF_ATTACHED   0x1     // arena is attached to list
#define NAIF_REDIRECT   0x2     // arena mmap has been redirected
#define NAIF_DEFUNCT    0x4     // arena is now defunct

struct necp_fd_data {
	u_int8_t necp_fd_type;
	LIST_ENTRY(necp_fd_data) chain;
	struct _necp_client_tree clients;
	struct _necp_fd_flow_tree flows;
	TAILQ_HEAD(_necp_client_update_list, necp_client_update) update_list;
	int update_count;
	int flags;

	unsigned background : 1;

	int proc_pid;
	decl_lck_mtx_data(, fd_lock);
	struct selinfo si;
#if SKYWALK
	// Arenas and their mmap info for per-process stats.  Stats objects are allocated from an active arena
	// that is not redirected/defunct.  The stats_arena_active keeps track of such an arena, and it also
	// holds a reference count on the object.  Each flow allocating a stats object also holds a reference
	// the necp_arena_info (where the object got allocated from).  During defunct, we redirect the mapping
	// of the arena such that any attempt to access (read/write) will result in getting zero-filled pages.
	// We then go thru all of the flows for the process and free the stats objects associated with them,
	// followed by destroying the skmem region(s) associated with the arena.  The stats_arena_list keeps
	// track of all current and defunct stats arenas; there could be more than one arena created for the
	// process as the arena destruction happens when its reference count drops to 0.
	struct necp_arena_info *stats_arena_active;
	LIST_HEAD(_necp_arena_info_list, necp_arena_info) stats_arena_list;
	u_int32_t stats_arena_gencnt;

	struct skmem_arena *sysctl_arena;
	struct skmem_arena_mmap_info sysctl_mmap;
	mach_vm_offset_t system_sysctls_roff;
#endif /* !SKYWALK */
};

#define NECP_FD_LOCK(_f) lck_mtx_lock(&_f->fd_lock)
#define NECP_FD_UNLOCK(_f) lck_mtx_unlock(&_f->fd_lock)
#define NECP_FD_ASSERT_LOCKED(_f) LCK_MTX_ASSERT(&_f->fd_lock, LCK_MTX_ASSERT_OWNED)
#define NECP_FD_ASSERT_UNLOCKED(_f) LCK_MTX_ASSERT(&_f->fd_lock, LCK_MTX_ASSERT_NOTOWNED)

static LIST_HEAD(_necp_fd_list, necp_fd_data) necp_fd_list;
static LIST_HEAD(_necp_fd_observer_list, necp_fd_data) necp_fd_observer_list;

static ZONE_DECLARE(necp_client_fd_zone, "necp.clientfd",
    sizeof(struct necp_fd_data), ZC_NONE);

#define NECP_FLOW_ZONE_NAME                     "necp.flow"
#define NECP_FLOW_REGISTRATION_ZONE_NAME        "necp.flowregistration"

static unsigned int necp_flow_size;             /* size of necp_client_flow */
static struct mcache *necp_flow_cache;  /* cache for necp_client_flow */

static unsigned int necp_flow_registration_size;        /* size of necp_client_flow_registration */
static struct mcache *necp_flow_registration_cache;     /* cache for necp_client_flow_registration */

#if SKYWALK
static ZONE_DECLARE(necp_arena_info_zone, "necp.arenainfo",
    sizeof(struct necp_arena_info), ZC_ZFREE_CLEARMEM);
#endif /* !SKYWALK */

static LCK_ATTR_DECLARE(necp_fd_mtx_attr, 0, 0);
static LCK_GRP_DECLARE(necp_fd_mtx_grp, "necp_fd");

static LCK_RW_DECLARE_ATTR(necp_fd_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);
static LCK_RW_DECLARE_ATTR(necp_observer_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);
static LCK_RW_DECLARE_ATTR(necp_client_tree_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);
static LCK_RW_DECLARE_ATTR(necp_flow_tree_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);
static LCK_RW_DECLARE_ATTR(necp_collect_stats_list_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);


#define NECP_STATS_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_collect_stats_list_lock)
#define NECP_STATS_LIST_LOCK_SHARED() lck_rw_lock_shared(&necp_collect_stats_list_lock)
#define NECP_STATS_LIST_UNLOCK() lck_rw_done(&necp_collect_stats_list_lock)

#define NECP_CLIENT_TREE_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_client_tree_lock)
#define NECP_CLIENT_TREE_LOCK_SHARED() lck_rw_lock_shared(&necp_client_tree_lock)
#define NECP_CLIENT_TREE_UNLOCK() lck_rw_done(&necp_client_tree_lock)
#define NECP_CLIENT_TREE_ASSERT_LOCKED() LCK_RW_ASSERT(&necp_client_tree_lock, LCK_RW_ASSERT_HELD)

#define NECP_FLOW_TREE_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_flow_tree_lock)
#define NECP_FLOW_TREE_LOCK_SHARED() lck_rw_lock_shared(&necp_flow_tree_lock)
#define NECP_FLOW_TREE_UNLOCK() lck_rw_done(&necp_flow_tree_lock)
#define NECP_FLOW_TREE_ASSERT_LOCKED() LCK_RW_ASSERT(&necp_flow_tree_lock, LCK_RW_ASSERT_HELD)

#define NECP_FD_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_fd_lock)
#define NECP_FD_LIST_LOCK_SHARED() lck_rw_lock_shared(&necp_fd_lock)
#define NECP_FD_LIST_UNLOCK() lck_rw_done(&necp_fd_lock)

#define NECP_OBSERVER_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&necp_observer_lock)
#define NECP_OBSERVER_LIST_LOCK_SHARED() lck_rw_lock_shared(&necp_observer_lock)
#define NECP_OBSERVER_LIST_UNLOCK() lck_rw_done(&necp_observer_lock)

// Locking Notes

// Take NECP_FD_LIST_LOCK when accessing or modifying the necp_fd_list
// Take NECP_CLIENT_TREE_LOCK when accessing or modifying the necp_client_global_tree
// Take NECP_FLOW_TREE_LOCK when accessing or modifying the necp_client_flow_global_tree
// Take NECP_STATS_LIST_LOCK when accessing or modifying the necp_collect_stats_flow_list
// Take NECP_FD_LOCK when accessing or modifying an necp_fd_data entry
// Take NECP_CLIENT_LOCK when accessing or modifying a single necp_client
// Take NECP_CLIENT_ROUTE_LOCK when accessing or modifying a client's route

// Precedence, where 1 is the first lock that must be taken
// 1. NECP_FD_LIST_LOCK
// 2. NECP_FD_LOCK (any)
// 3. NECP_CLIENT_TREE_LOCK
// 4. NECP_CLIENT_LOCK (any)
// 5. NECP_FLOW_TREE_LOCK
// 6. NECP_STATS_LIST_LOCK
// 7. NECP_CLIENT_ROUTE_LOCK (any)

static thread_call_t necp_client_update_tcall;

#if SKYWALK
static thread_call_t necp_client_collect_stats_tcall;
static thread_call_t necp_close_empty_arenas_tcall;

static void necp_fd_insert_stats_arena(struct necp_fd_data *fd_data, struct necp_arena_info *nai);
static void necp_fd_remove_stats_arena(struct necp_fd_data *fd_data, struct necp_arena_info *nai);
static struct necp_arena_info *necp_fd_mredirect_stats_arena(struct necp_fd_data *fd_data, struct proc *proc);

static void necp_arena_info_retain(struct necp_arena_info *nai);
static void necp_arena_info_release(struct necp_arena_info *nai);
static struct necp_arena_info *necp_arena_info_alloc(void);
static void necp_arena_info_free(struct necp_arena_info *nai);

static int necp_arena_initialize(struct necp_fd_data *fd_data, bool locked);
static int necp_stats_initialize(struct necp_fd_data *fd_data, struct necp_client *client,
    struct necp_client_flow_registration *flow_registration, struct necp_stats_bufreq *bufreq);
static int necp_arena_create(struct necp_fd_data *fd_data, size_t obj_size, size_t obj_cnt, struct proc *p);
static int necp_arena_stats_obj_alloc(struct necp_fd_data *fd_data, mach_vm_offset_t *off, struct necp_arena_info **stats_arena, void **kstats_kaddr, boolean_t cansleep);
static void necp_arena_stats_obj_free(struct necp_fd_data *fd_data, struct necp_arena_info *stats_arena, void **kstats_kaddr, mach_vm_address_t *ustats_uaddr);
static void necp_stats_arenas_destroy(struct necp_fd_data *fd_data, boolean_t closing);

static int necp_sysctl_arena_initialize(struct necp_fd_data *fd_data, bool locked);
static void necp_sysctl_arena_destroy(struct necp_fd_data *fd_data);
static void *necp_arena_sysctls_obj(struct necp_fd_data *fd_data, mach_vm_offset_t *off, size_t *size);
#endif /* !SKYWALK */

/// NECP file descriptor functions

static void
necp_fd_notify(struct necp_fd_data *fd_data, bool locked)
{
	struct selinfo *si = &fd_data->si;

	if (!locked) {
		NECP_FD_LOCK(fd_data);
	}

	selwakeup(si);

	// use a non-zero hint to tell the notification from the
	// call done in kqueue_scan() which uses 0
	KNOTE(&si->si_note, 1); // notification

	if (!locked) {
		NECP_FD_UNLOCK(fd_data);
	}
}

static inline bool
necp_client_has_unread_flows(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);
	struct necp_client_flow_registration *flow_registration = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		if (!flow_registration->flow_result_read) {
			return true;
		}
	}
	return false;
}

static int
necp_fd_poll(struct necp_fd_data *fd_data, int events, void *wql, struct proc *p, int is_kevent)
{
#pragma unused(wql, p, is_kevent)
	u_int revents = 0;

	u_int want_rx = events & (POLLIN | POLLRDNORM);
	if (want_rx) {
		if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			// Push-mode observers are readable when they have a new update
			if (!TAILQ_EMPTY(&fd_data->update_list)) {
				revents |= want_rx;
			}
		} else {
			// Standard fds are readable when some client is unread
			struct necp_client *client = NULL;
			bool has_unread_clients = FALSE;
			RB_FOREACH(client, _necp_client_tree, &fd_data->clients) {
				NECP_CLIENT_LOCK(client);
				if (!client->result_read || !client->group_members_read || necp_client_has_unread_flows(client)) {
					has_unread_clients = TRUE;
				}
				NECP_CLIENT_UNLOCK(client);
				if (has_unread_clients) {
					break;
				}
			}

			if (has_unread_clients) {
				revents |= want_rx;
			}
		}
	}

	return revents;
}

static inline void
necp_generate_client_id(uuid_t client_id, bool is_flow)
{
	uuid_generate_random(client_id);

	if (is_flow) {
		client_id[9] |= 0x01;
	} else {
		client_id[9] &= ~0x01;
	}
}

static inline bool
necp_client_id_is_flow(uuid_t client_id)
{
	return client_id[9] & 0x01;
}

static struct necp_client *
necp_find_client_and_lock(uuid_t client_id)
{
	NECP_CLIENT_TREE_ASSERT_LOCKED();

	struct necp_client *client = NULL;

	if (necp_client_id_is_flow(client_id)) {
		NECP_FLOW_TREE_LOCK_SHARED();
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, client_id);
		struct necp_client_flow_registration *flow = RB_FIND(_necp_client_flow_global_tree, &necp_client_flow_global_tree, &find);
		if (flow != NULL) {
			client = flow->client;
		}
		NECP_FLOW_TREE_UNLOCK();
	} else {
		struct necp_client find;
		uuid_copy(find.client_id, client_id);
		client = RB_FIND(_necp_client_global_tree, &necp_client_global_tree, &find);
	}

	if (client != NULL) {
		NECP_CLIENT_LOCK(client);
	}

	return client;
}

static struct necp_client_flow_registration *
necp_client_find_flow(struct necp_client *client, uuid_t flow_id)
{
	NECP_CLIENT_ASSERT_LOCKED(client);
	struct necp_client_flow_registration *flow = NULL;

	if (necp_client_id_is_flow(flow_id)) {
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, flow_id);
		flow = RB_FIND(_necp_client_flow_tree, &client->flow_registrations, &find);
	} else {
		flow = RB_ROOT(&client->flow_registrations);
	}

	return flow;
}

static struct necp_client *
necp_client_fd_find_client_unlocked(struct necp_fd_data *client_fd, uuid_t client_id)
{
	NECP_FD_ASSERT_LOCKED(client_fd);
	struct necp_client *client = NULL;

	if (necp_client_id_is_flow(client_id)) {
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, client_id);
		struct necp_client_flow_registration *flow = RB_FIND(_necp_fd_flow_tree, &client_fd->flows, &find);
		if (flow != NULL) {
			client = flow->client;
		}
	} else {
		struct necp_client find;
		uuid_copy(find.client_id, client_id);
		client = RB_FIND(_necp_client_tree, &client_fd->clients, &find);
	}

	return client;
}

static struct necp_client *
necp_client_fd_find_client_and_lock(struct necp_fd_data *client_fd, uuid_t client_id)
{
	struct necp_client *client = necp_client_fd_find_client_unlocked(client_fd, client_id);
	if (client != NULL) {
		NECP_CLIENT_LOCK(client);
	}

	return client;
}

static inline int
necp_client_id_cmp(struct necp_client *client0, struct necp_client *client1)
{
	return uuid_compare(client0->client_id, client1->client_id);
}

static inline int
necp_client_flow_id_cmp(struct necp_client_flow_registration *flow0, struct necp_client_flow_registration *flow1)
{
	return uuid_compare(flow0->registration_id, flow1->registration_id);
}

static int
necpop_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
#pragma unused(fp, which, wql, ctx)
	return 0;
	struct necp_fd_data *fd_data = NULL;
	int revents = 0;
	int events = 0;
	proc_t procp;

	fd_data = (struct necp_fd_data *)fp_get_data(fp);
	if (fd_data == NULL) {
		return 0;
	}

	procp = vfs_context_proc(ctx);

	switch (which) {
	case FREAD: {
		events = POLLIN;
		break;
	}

	default: {
		return 1;
	}
	}

	NECP_FD_LOCK(fd_data);
	revents = necp_fd_poll(fd_data, events, wql, procp, 0);
	NECP_FD_UNLOCK(fd_data);

	return (events & revents) ? 1 : 0;
}

static void
necp_fd_knrdetach(struct knote *kn)
{
	struct necp_fd_data *fd_data = (struct necp_fd_data *)kn->kn_hook;
	struct selinfo *si = &fd_data->si;

	NECP_FD_LOCK(fd_data);
	KNOTE_DETACH(&si->si_note, kn);
	NECP_FD_UNLOCK(fd_data);
}

static int
necp_fd_knread(struct knote *kn, long hint)
{
#pragma unused(kn, hint)
	return 1; /* assume we are ready */
}

static int
necp_fd_knrprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	struct necp_fd_data *fd_data;
	int revents;
	int res;

	fd_data = (struct necp_fd_data *)kn->kn_hook;

	NECP_FD_LOCK(fd_data);
	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);
	res = ((revents & POLLIN) != 0);
	if (res) {
		knote_fill_kevent(kn, kev, 0);
	}
	NECP_FD_UNLOCK(fd_data);
	return res;
}

static int
necp_fd_knrtouch(struct knote *kn, struct kevent_qos_s *kev)
{
#pragma unused(kev)
	struct necp_fd_data *fd_data;
	int revents;

	fd_data = (struct necp_fd_data *)kn->kn_hook;

	NECP_FD_LOCK(fd_data);
	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);
	NECP_FD_UNLOCK(fd_data);

	return (revents & POLLIN) != 0;
}

SECURITY_READ_ONLY_EARLY(struct filterops) necp_fd_rfiltops = {
	.f_isfd = 1,
	.f_detach = necp_fd_knrdetach,
	.f_event = necp_fd_knread,
	.f_touch = necp_fd_knrtouch,
	.f_process = necp_fd_knrprocess,
};

static int
necpop_kqfilter(struct fileproc *fp, struct knote *kn,
    __unused struct kevent_qos_s *kev)
{
	struct necp_fd_data *fd_data = NULL;
	int revents;

	if (kn->kn_filter != EVFILT_READ) {
		NECPLOG(LOG_ERR, "bad filter request %d", kn->kn_filter);
		knote_set_error(kn, EINVAL);
		return 0;
	}

	fd_data = (struct necp_fd_data *)fp_get_data(fp);
	if (fd_data == NULL) {
		NECPLOG0(LOG_ERR, "No channel for kqfilter");
		knote_set_error(kn, ENOENT);
		return 0;
	}

	NECP_FD_LOCK(fd_data);
	kn->kn_filtid = EVFILTID_NECP_FD;
	kn->kn_hook = fd_data;
	KNOTE_ATTACH(&fd_data->si.si_note, kn);

	revents = necp_fd_poll(fd_data, POLLIN, NULL, current_proc(), 1);

	NECP_FD_UNLOCK(fd_data);

	return (revents & POLLIN) != 0;
}

#define INTERFACE_FLAGS_SHIFT   32
#define INTERFACE_FLAGS_MASK    0xffff
#define INTERFACE_INDEX_SHIFT   0
#define INTERFACE_INDEX_MASK    0xffffffff

static uint64_t
combine_interface_details(uint32_t interface_index, uint16_t interface_flags)
{
	return ((uint64_t)interface_flags & INTERFACE_FLAGS_MASK) << INTERFACE_FLAGS_SHIFT |
	       ((uint64_t)interface_index & INTERFACE_INDEX_MASK) << INTERFACE_INDEX_SHIFT;
}

#if SKYWALK

static void
split_interface_details(uint64_t combined_details, uint32_t *interface_index, uint16_t *interface_flags)
{
	*interface_index = (combined_details >> INTERFACE_INDEX_SHIFT) & INTERFACE_INDEX_MASK;
	*interface_flags = (combined_details >> INTERFACE_FLAGS_SHIFT) & INTERFACE_FLAGS_MASK;
}

static void
necp_flow_save_current_interface_details(struct necp_client_flow_registration *flow_registration)
{
	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (flow->nexus) {
			uint64_t combined_details = combine_interface_details(flow->interface_index, flow->interface_flags);
			atomic_set_64(&flow_registration->last_interface_details, combined_details);
			break;
		}
	}
}

static void
necp_client_collect_interface_stats(struct necp_client_flow_registration *flow_registration, struct ifnet_stats_per_flow *ifs)
{
	struct necp_client_flow *flow = NULL;

	if (ifs == NULL || ifs->txpackets == 0 || ifs->rxpackets == 0) {
		return; // App might have crashed without publishing ifs
	}

	// Do malicious stats detection here

	// Fold userspace stats into (trusted) kernel stats (stored in ifp).
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		uint32_t if_idx = flow->interface_index;
		ifnet_t ifp = NULL;
		ifnet_head_lock_shared();
		if (if_idx != IFSCOPE_NONE && if_idx <= (uint32_t)if_index) {
			ifp = ifindex2ifnet[if_idx];
			ifnet_update_stats_per_flow(ifs, ifp);
		}
		ifnet_head_done();

		// Currently there is only one flow that uses the shared necp
		// stats region, so this loop should exit after updating an ifp
		break;
	}
}

static void
necp_client_collect_stats(struct necp_client_flow_registration *flow_registration)
{
	struct necp_all_kstats *kstats = (struct necp_all_kstats *)flow_registration->kstats_kaddr;
	if (kstats == NULL) {
		return;
	}

	// Grab userspace stats delta (untrusted).
	struct necp_tcp_stats *curr_tcpstats = (struct necp_tcp_stats *)kstats->necp_stats_ustats;
	struct necp_tcp_stats *prev_tcpstats = (struct necp_tcp_stats *)&kstats->necp_stats_comm;
#define diff_n_update(field)    \
	u_int32_t d_##field = (curr_tcpstats->necp_tcp_counts.necp_stat_##field - prev_tcpstats->necp_tcp_counts.necp_stat_##field);    \
	prev_tcpstats->necp_tcp_counts.necp_stat_##field += d_##field;
	diff_n_update(rxpackets);
	diff_n_update(txpackets);
	if (d_rxpackets == 0 && d_txpackets == 0) {
		return; // no activity since last collection, stop here
	}
	diff_n_update(rxbytes);
	diff_n_update(txbytes);
	diff_n_update(rxduplicatebytes);
	diff_n_update(rxoutoforderbytes);
	diff_n_update(txretransmit);
	diff_n_update(connectattempts);
	diff_n_update(connectsuccesses);
	uint32_t rtt = prev_tcpstats->necp_tcp_counts.necp_stat_avg_rtt = curr_tcpstats->necp_tcp_counts.necp_stat_avg_rtt;
	uint32_t rtt_var = prev_tcpstats->necp_tcp_counts.necp_stat_var_rtt = curr_tcpstats->necp_tcp_counts.necp_stat_var_rtt;
#undef diff_n_update

	// Do malicious stats detection with the deltas here.
	// RTT check (not necessarily attacks, might just be not measured since we report stats async periodically).
	if (rtt < necp_client_stats_rtt_floor || rtt > necp_client_stats_rtt_ceiling) {
		rtt = rtt_var = 0;      // nstat_route_update to skip 0 rtt
	}

	// Fold userspace stats into (trusted) kernel stats (stored in route).
	NECP_CLIENT_ROUTE_LOCK(flow_registration->client);
	struct rtentry *route = flow_registration->client->current_route;
	if (route != NULL) {
		nstat_route_update(route, d_connectattempts, d_connectsuccesses, d_rxpackets, d_rxbytes, d_rxduplicatebytes,
		    d_rxoutoforderbytes, d_txpackets, d_txbytes, d_txretransmit, rtt, rtt_var);
	}
	NECP_CLIENT_ROUTE_UNLOCK(flow_registration->client);
}

// This is called from various places; "closing" here implies the client being closed/removed if true, otherwise being
// defunct.  In the former, we expect the caller to not hold the lock; for the latter it must have acquired it.
static void
necp_destroy_flow_stats(struct necp_fd_data *fd_data,
    struct necp_client_flow_registration *flow_registration,
    struct ifnet_stats_per_flow *flow_ifnet_stats,
    boolean_t closing)
{
	NECP_FD_ASSERT_LOCKED(fd_data);

	struct necp_client *client = flow_registration->client;

	if (closing) {
		NECP_CLIENT_ASSERT_UNLOCKED(client);
		NECP_CLIENT_LOCK(client);
	} else {
		NECP_CLIENT_ASSERT_LOCKED(client);
	}

	// the interface stats are independent of the flow stats, hence we check here
	if (flow_ifnet_stats != NULL) {
		necp_client_collect_interface_stats(flow_registration, flow_ifnet_stats);
	}

	if (flow_registration->kstats_kaddr != NULL) {
		NECP_STATS_LIST_LOCK_EXCLUSIVE();
		necp_client_collect_stats(flow_registration);
		const bool destroyed = necp_client_release_locked(client); // Drop the reference held by the stats list
		ASSERT(!destroyed);
		(void)destroyed;
		LIST_REMOVE(flow_registration, collect_stats_chain);
		NECP_STATS_LIST_UNLOCK();
		if (flow_registration->stats_handler_context != NULL) {
			ntstat_userland_stats_close(flow_registration->stats_handler_context);
			flow_registration->stats_handler_context = NULL;
		}
		necp_arena_stats_obj_free(fd_data, flow_registration->stats_arena, &flow_registration->kstats_kaddr, &flow_registration->ustats_uaddr);
		ASSERT(flow_registration->kstats_kaddr == NULL);
		ASSERT(flow_registration->ustats_uaddr == 0);
	}

	if (flow_registration->nexus_stats != NULL) {
		flow_stats_release(flow_registration->nexus_stats);
		flow_registration->nexus_stats = NULL;
	}

	if (closing) {
		NECP_CLIENT_UNLOCK(client);
	}
}

static void
necp_schedule_collect_stats_clients(bool recur)
{
	if (necp_client_collect_stats_tcall == NULL ||
	    (!recur && thread_call_isactive(necp_client_collect_stats_tcall))) {
		return;
	}

	uint64_t deadline = 0;
	uint64_t leeway = 0;
	clock_interval_to_deadline(necp_collect_stats_timeout_microseconds, NSEC_PER_USEC, &deadline);
	clock_interval_to_absolutetime_interval(necp_collect_stats_timeout_leeway_microseconds, NSEC_PER_USEC, &leeway);

	thread_call_enter_delayed_with_leeway(necp_client_collect_stats_tcall, NULL,
	    deadline, leeway, THREAD_CALL_DELAY_LEEWAY);
}

static void
necp_collect_stats_client_callout(__unused thread_call_param_t dummy,
    __unused thread_call_param_t arg)
{
	struct necp_client_flow_registration *flow_registration;

	net_update_uptime();
	NECP_STATS_LIST_LOCK_SHARED();
	if (LIST_EMPTY(&necp_collect_stats_flow_list)) {
		NECP_STATS_LIST_UNLOCK();
		return;
	}
	LIST_FOREACH(flow_registration, &necp_collect_stats_flow_list, collect_stats_chain) {
		// Collecting stats should be cheap (atomic increments)
		// Values like flow_registration->kstats_kaddr are guaranteed to be valid
		// as long as the flow_registration is in the stats list
		necp_client_collect_stats(flow_registration);
	}
	NECP_STATS_LIST_UNLOCK();

	necp_schedule_collect_stats_clients(TRUE); // recurring collection
}

#endif /* !SKYWALK */

static void
necp_defunct_flow_registration(struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    struct _necp_flow_defunct_list *defunct_list)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	if (!flow_registration->defunct) {
		bool needs_defunct = false;
		struct necp_client_flow *search_flow = NULL;
		LIST_FOREACH(search_flow, &flow_registration->flow_list, flow_chain) {
			if (search_flow->nexus &&
			    !uuid_is_null(search_flow->u.nexus_agent)) {
				// Save defunct values for the nexus
				if (defunct_list != NULL) {
					// Sleeping alloc won't fail; copy only what's necessary
					struct necp_flow_defunct *flow_defunct = kalloc_type(struct necp_flow_defunct,
					    Z_WAITOK | Z_ZERO);
					uuid_copy(flow_defunct->nexus_agent, search_flow->u.nexus_agent);
					uuid_copy(flow_defunct->flow_id, ((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
					    client->client_id :
					    flow_registration->registration_id));
					flow_defunct->proc_pid = client->proc_pid;
					flow_defunct->agent_handle = client->agent_handle;
					flow_defunct->flags = flow_registration->flags;
#if SKYWALK
					if (flow_registration->kstats_kaddr != NULL) {
						struct necp_all_stats *ustats_kaddr = ((struct necp_all_kstats *)flow_registration->kstats_kaddr)->necp_stats_ustats;
						struct necp_quic_stats *quicstats = (struct necp_quic_stats *)ustats_kaddr;
						if (quicstats != NULL) {
							memcpy(flow_defunct->close_parameters.u.close_token, quicstats->necp_quic_extra.ssr_token, sizeof(flow_defunct->close_parameters.u.close_token));
							flow_defunct->has_close_parameters = true;
						}
					}
#endif /* SKYWALK */
					// Add to the list provided by caller
					LIST_INSERT_HEAD(defunct_list, flow_defunct, chain);
				}

				needs_defunct = true;
			}
		}

		if (needs_defunct) {
#if SKYWALK
			// Close the stats early
			if (flow_registration->stats_handler_context != NULL) {
				ntstat_userland_stats_event(flow_registration->stats_handler_context,
				    NECP_CLIENT_STATISTICS_EVENT_TIME_WAIT);
			}
#endif /* SKYWALK */

			// Only set defunct if there was some assigned flow
			flow_registration->defunct = true;
		}
	}
}

static void
necp_defunct_client_for_policy(struct necp_client *client,
    struct _necp_flow_defunct_list *defunct_list)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	struct necp_client_flow_registration *flow_registration = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		necp_defunct_flow_registration(client, flow_registration, defunct_list);
	}
}

static void
necp_client_free(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_UNLOCKED(client);

	kfree_data(client->extra_interface_options,
	    sizeof(struct necp_client_interface_option) * NECP_CLIENT_INTERFACE_OPTION_EXTRA_COUNT);
	client->extra_interface_options = NULL;

	kfree_data(client->parameters, client->parameters_length);
	client->parameters = NULL;

	lck_mtx_destroy(&client->route_lock, &necp_fd_mtx_grp);
	lck_mtx_destroy(&client->lock, &necp_fd_mtx_grp);

	kfree_type(struct necp_client, client);
}

static void
necp_client_retain_locked(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	os_ref_retain_locked(&client->reference_count);
}

static void
necp_client_retain(struct necp_client *client)
{
	NECP_CLIENT_LOCK(client);
	necp_client_retain_locked(client);
	NECP_CLIENT_UNLOCK(client);
}

static bool
necp_client_release_locked(struct necp_client *client)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	os_ref_count_t count = os_ref_release_locked(&client->reference_count);
	if (count == 0) {
		NECP_CLIENT_UNLOCK(client);
		necp_client_free(client);
	}

	return count == 0;
}

static bool
necp_client_release(struct necp_client *client)
{
	bool last_ref;

	NECP_CLIENT_LOCK(client);
	if (!(last_ref = necp_client_release_locked(client))) {
		NECP_CLIENT_UNLOCK(client);
	}

	return last_ref;
}

static struct necp_client_update *
necp_client_update_alloc(const void *data, size_t length)
{
	struct necp_client_update *client_update;
	struct necp_client_observer_update *buffer;
	size_t alloc_size;

	if (os_add_overflow(length, sizeof(*buffer), &alloc_size)) {
		return NULL;
	}
	buffer = kalloc_data(alloc_size, Z_WAITOK);
	if (buffer == NULL) {
		return NULL;
	}

	client_update = kalloc_type(struct necp_client_update,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	client_update->update_length = alloc_size;
	client_update->update = buffer;
	memcpy(buffer->tlv_buffer, data, length);
	return client_update;
}

static void
necp_client_update_free(struct necp_client_update *client_update)
{
	kfree_data(client_update->update, client_update->update_length);
	kfree_type(struct necp_client_update, client_update);
}

static void
necp_client_update_observer_add_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
{
	struct necp_client_update *client_update;

	NECP_FD_LOCK(observer_fd);

	if (observer_fd->update_count >= necp_observer_message_limit) {
		NECP_FD_UNLOCK(observer_fd);
		return;
	}

	client_update = necp_client_update_alloc(client->parameters, client->parameters_length);
	if (client_update != NULL) {
		uuid_copy(client_update->client_id, client->client_id);
		client_update->update->update_type = NECP_CLIENT_UPDATE_TYPE_PARAMETERS;
		TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain);
		observer_fd->update_count++;

		necp_fd_notify(observer_fd, true);
	}

	NECP_FD_UNLOCK(observer_fd);
}

static void
necp_client_update_observer_update_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
{
	NECP_FD_LOCK(observer_fd);

	if (observer_fd->update_count >= necp_observer_message_limit) {
		NECP_FD_UNLOCK(observer_fd);
		return;
	}

	struct necp_client_update *client_update = necp_client_update_alloc(client->result, client->result_length);
	if (client_update != NULL) {
		uuid_copy(client_update->client_id, client->client_id);
		client_update->update->update_type = NECP_CLIENT_UPDATE_TYPE_RESULT;
		TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain);
		observer_fd->update_count++;

		necp_fd_notify(observer_fd, true);
	}

	NECP_FD_UNLOCK(observer_fd);
}

static void
necp_client_update_observer_remove_internal(struct necp_fd_data *observer_fd, struct necp_client *client)
{
	NECP_FD_LOCK(observer_fd);

	if (observer_fd->update_count >= necp_observer_message_limit) {
		NECP_FD_UNLOCK(observer_fd);
		return;
	}

	struct necp_client_update *client_update = necp_client_update_alloc(NULL, 0);
	if (client_update != NULL) {
		uuid_copy(client_update->client_id, client->client_id);
		client_update->update->update_type = NECP_CLIENT_UPDATE_TYPE_REMOVE;
		TAILQ_INSERT_TAIL(&observer_fd->update_list, client_update, chain);
		observer_fd->update_count++;

		necp_fd_notify(observer_fd, true);
	}

	NECP_FD_UNLOCK(observer_fd);
}

static void
necp_client_update_observer_add(struct necp_client *client)
{
	NECP_OBSERVER_LIST_LOCK_SHARED();

	if (LIST_EMPTY(&necp_fd_observer_list)) {
		// No observers, bail
		NECP_OBSERVER_LIST_UNLOCK();
		return;
	}

	struct necp_fd_data *observer_fd = NULL;
	LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		necp_client_update_observer_add_internal(observer_fd, client);
	}

	NECP_OBSERVER_LIST_UNLOCK();
}

static void
necp_client_update_observer_update(struct necp_client *client)
{
	NECP_OBSERVER_LIST_LOCK_SHARED();

	if (LIST_EMPTY(&necp_fd_observer_list)) {
		// No observers, bail
		NECP_OBSERVER_LIST_UNLOCK();
		return;
	}

	struct necp_fd_data *observer_fd = NULL;
	LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		necp_client_update_observer_update_internal(observer_fd, client);
	}

	NECP_OBSERVER_LIST_UNLOCK();
}

static void
necp_client_update_observer_remove(struct necp_client *client)
{
	NECP_OBSERVER_LIST_LOCK_SHARED();

	if (LIST_EMPTY(&necp_fd_observer_list)) {
		// No observers, bail
		NECP_OBSERVER_LIST_UNLOCK();
		return;
	}

	struct necp_fd_data *observer_fd = NULL;
	LIST_FOREACH(observer_fd, &necp_fd_observer_list, chain) {
		necp_client_update_observer_remove_internal(observer_fd, client);
	}

	NECP_OBSERVER_LIST_UNLOCK();
}

static void
necp_destroy_client_flow_registration(struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    pid_t pid, bool abort)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	bool has_close_parameters = false;
	struct necp_client_agent_parameters close_parameters = {};
	memset(close_parameters.u.close_token, 0, sizeof(close_parameters.u.close_token));
#if SKYWALK
	if (flow_registration->kstats_kaddr != NULL) {
		struct necp_all_stats *ustats_kaddr = ((struct necp_all_kstats *)flow_registration->kstats_kaddr)->necp_stats_ustats;
		struct necp_quic_stats *quicstats = (struct necp_quic_stats *)ustats_kaddr;
		if (quicstats != NULL &&
		    quicstats->necp_quic_udp_stats.necp_udp_hdr.necp_stats_type == NECP_CLIENT_STATISTICS_TYPE_QUIC) {
			memcpy(close_parameters.u.close_token, quicstats->necp_quic_extra.ssr_token, sizeof(close_parameters.u.close_token));
			has_close_parameters = true;
		}
	}

	// Release reference held on the stats arena
	if (flow_registration->stats_arena != NULL) {
		necp_arena_info_release(flow_registration->stats_arena);
		flow_registration->stats_arena = NULL;
	}
#endif /* SKYWALK */

	struct necp_client_flow *search_flow = NULL;
	struct necp_client_flow *temp_flow = NULL;
	LIST_FOREACH_SAFE(search_flow, &flow_registration->flow_list, flow_chain, temp_flow) {
		if (search_flow->nexus &&
		    !uuid_is_null(search_flow->u.nexus_agent)) {
			// Don't unregister for defunct flows
			if (!flow_registration->defunct) {
				u_int8_t message_type = (abort ? NETAGENT_MESSAGE_TYPE_ABORT_NEXUS :
				    NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS);
				if (((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_BROWSE) ||
				    (flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_RESOLVE)) &&
				    !(flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_ALLOW_NEXUS)) {
					message_type = NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT;
				}
				int netagent_error = netagent_client_message_with_params(search_flow->u.nexus_agent,
				    ((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
				    client->client_id :
				    flow_registration->registration_id),
				    pid, client->agent_handle,
				    message_type,
				    has_close_parameters ? &close_parameters : NULL,
				    NULL, 0);
				if (netagent_error != 0 && netagent_error != ENOENT) {
					NECPLOG(LOG_ERR, "necp_client_remove close nexus error (%d) MESSAGE TYPE %u", netagent_error, message_type);
				}
			}
			uuid_clear(search_flow->u.nexus_agent);
		}
		if (search_flow->assigned_results != NULL) {
			kfree_data(search_flow->assigned_results, search_flow->assigned_results_length);
			search_flow->assigned_results = NULL;
		}
		LIST_REMOVE(search_flow, flow_chain);
#if SKYWALK
		if (search_flow->nexus) {
			OSDecrementAtomic(&necp_nexus_flow_count);
		} else
#endif /* SKYWALK */
		if (search_flow->socket) {
			OSDecrementAtomic(&necp_socket_flow_count);
		} else {
			OSDecrementAtomic(&necp_if_flow_count);
		}
		mcache_free(necp_flow_cache, search_flow);
	}

	RB_REMOVE(_necp_client_flow_tree, &client->flow_registrations, flow_registration);
	flow_registration->client = NULL;

	mcache_free(necp_flow_registration_cache, flow_registration);
}

static void
necp_destroy_client(struct necp_client *client, pid_t pid, bool abort)
{
	NECP_CLIENT_ASSERT_UNLOCKED(client);

#if SKYWALK
	if (client->nstat_context != NULL) {
		// This is a catch-all that should be rarely used.
		nstat_provider_stats_close(client->nstat_context);
		client->nstat_context = NULL;
	}
	if (client->original_parameters_source != NULL) {
		necp_client_release(client->original_parameters_source);
		client->original_parameters_source = NULL;
	}
#endif /* SKYWALK */
	necp_client_update_observer_remove(client);

	NECP_CLIENT_LOCK(client);

	// Free route
	NECP_CLIENT_ROUTE_LOCK(client);
	if (client->current_route != NULL) {
		rtfree(client->current_route);
		client->current_route = NULL;
	}
	NECP_CLIENT_ROUTE_UNLOCK(client);

	// Remove flow assignments
	struct necp_client_flow_registration *flow_registration = NULL;
	struct necp_client_flow_registration *temp_flow_registration = NULL;
	RB_FOREACH_SAFE(flow_registration, _necp_client_flow_tree, &client->flow_registrations, temp_flow_registration) {
		necp_destroy_client_flow_registration(client, flow_registration, pid, abort);
	}

#if SKYWALK
	// Remove port reservation
	if (NETNS_TOKEN_VALID(&client->port_reservation)) {
		netns_release(&client->port_reservation);
	}
#endif /* !SKYWALK */

	// Remove agent assertions
	struct necp_client_assertion *search_assertion = NULL;
	struct necp_client_assertion *temp_assertion = NULL;
	LIST_FOREACH_SAFE(search_assertion, &client->assertion_list, assertion_chain, temp_assertion) {
		int netagent_error = netagent_client_message(search_assertion->asserted_netagent, client->client_id, pid,
		    client->agent_handle, NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT);
		if (netagent_error != 0) {
			NECPLOG((netagent_error == ENOENT ? LOG_DEBUG : LOG_ERR),
			    "necp_client_remove unassert agent error (%d)", netagent_error);
		}
		LIST_REMOVE(search_assertion, assertion_chain);
		kfree_type(struct necp_client_assertion, search_assertion);
	}

	if (!necp_client_release_locked(client)) {
		NECP_CLIENT_UNLOCK(client);
	}

	OSDecrementAtomic(&necp_client_count);
}

static bool
necp_defunct_client_fd_locked_inner(struct necp_fd_data *client_fd, struct _necp_flow_defunct_list *defunct_list, bool destroy_stats);

static void
necp_process_defunct_list(struct _necp_flow_defunct_list *defunct_list)
{
	if (!LIST_EMPTY(defunct_list)) {
		struct necp_flow_defunct *flow_defunct = NULL;
		struct necp_flow_defunct *temp_flow_defunct = NULL;

		// For each newly defunct client, send a message to the nexus to remove the flow
		LIST_FOREACH_SAFE(flow_defunct, defunct_list, chain, temp_flow_defunct) {
			if (!uuid_is_null(flow_defunct->nexus_agent)) {
				u_int8_t message_type = NETAGENT_MESSAGE_TYPE_ABORT_NEXUS;
				if (((flow_defunct->flags & NECP_CLIENT_FLOW_FLAGS_BROWSE) ||
				    (flow_defunct->flags & NECP_CLIENT_FLOW_FLAGS_RESOLVE)) &&
				    !(flow_defunct->flags & NECP_CLIENT_FLOW_FLAGS_ALLOW_NEXUS)) {
					message_type = NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT;
				}
				int netagent_error = netagent_client_message_with_params(flow_defunct->nexus_agent,
				    flow_defunct->flow_id,
				    flow_defunct->proc_pid,
				    flow_defunct->agent_handle,
				    message_type,
				    flow_defunct->has_close_parameters ? &flow_defunct->close_parameters : NULL,
				    NULL, 0);
				if (netagent_error != 0) {
					char namebuf[MAXCOMLEN + 1];
					(void) strlcpy(namebuf, "unknown", sizeof(namebuf));
					proc_name(flow_defunct->proc_pid, namebuf, sizeof(namebuf));
					NECPLOG((netagent_error == ENOENT ? LOG_DEBUG : LOG_ERR), "necp_update_client abort nexus error (%d) for pid %d %s", netagent_error, flow_defunct->proc_pid, namebuf);
				}
			}
			LIST_REMOVE(flow_defunct, chain);
			kfree_type(struct necp_flow_defunct, flow_defunct);
		}
	}
	ASSERT(LIST_EMPTY(defunct_list));
}

static int
necpop_close(struct fileglob *fg, vfs_context_t ctx)
{
#pragma unused(ctx)
	struct necp_fd_data *fd_data = NULL;
	int error = 0;

	fd_data = (struct necp_fd_data *)fg_get_data(fg);
	fg_set_data(fg, NULL);

	if (fd_data != NULL) {
		struct _necp_client_tree clients_to_close;
		RB_INIT(&clients_to_close);

		// Remove from list quickly
		if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			NECP_OBSERVER_LIST_LOCK_EXCLUSIVE();
			LIST_REMOVE(fd_data, chain);
			NECP_OBSERVER_LIST_UNLOCK();
		} else {
			NECP_FD_LIST_LOCK_EXCLUSIVE();
			LIST_REMOVE(fd_data, chain);
			NECP_FD_LIST_UNLOCK();
		}

		NECP_FD_LOCK(fd_data);
		pid_t pid = fd_data->proc_pid;

		struct _necp_flow_defunct_list defunct_list;
		LIST_INIT(&defunct_list);

		(void)necp_defunct_client_fd_locked_inner(fd_data, &defunct_list, false);

		struct necp_client_flow_registration *flow_registration = NULL;
		struct necp_client_flow_registration *temp_flow_registration = NULL;
		RB_FOREACH_SAFE(flow_registration, _necp_fd_flow_tree, &fd_data->flows, temp_flow_registration) {
#if SKYWALK
			necp_destroy_flow_stats(fd_data, flow_registration, NULL, TRUE);
#endif /* SKYWALK */
			NECP_FLOW_TREE_LOCK_EXCLUSIVE();
			RB_REMOVE(_necp_client_flow_global_tree, &necp_client_flow_global_tree, flow_registration);
			NECP_FLOW_TREE_UNLOCK();
			RB_REMOVE(_necp_fd_flow_tree, &fd_data->flows, flow_registration);
		}

		struct necp_client *client = NULL;
		struct necp_client *temp_client = NULL;
		RB_FOREACH_SAFE(client, _necp_client_tree, &fd_data->clients, temp_client) {
			NECP_CLIENT_TREE_LOCK_EXCLUSIVE();
			RB_REMOVE(_necp_client_global_tree, &necp_client_global_tree, client);
			NECP_CLIENT_TREE_UNLOCK();
			RB_REMOVE(_necp_client_tree, &fd_data->clients, client);
			RB_INSERT(_necp_client_tree, &clients_to_close, client);
		}

		struct necp_client_update *client_update = NULL;
		struct necp_client_update *temp_update = NULL;
		TAILQ_FOREACH_SAFE(client_update, &fd_data->update_list, chain, temp_update) {
			// Flush pending updates
			TAILQ_REMOVE(&fd_data->update_list, client_update, chain);
			necp_client_update_free(client_update);
		}
		fd_data->update_count = 0;

#if SKYWALK
		// Cleanup stats arena(s); indicate that we're closing
		necp_stats_arenas_destroy(fd_data, TRUE);
		ASSERT(fd_data->stats_arena_active == NULL);
		ASSERT(LIST_EMPTY(&fd_data->stats_arena_list));

		// Cleanup systctl arena
		necp_sysctl_arena_destroy(fd_data);
		ASSERT(fd_data->sysctl_arena == NULL);
#endif /* SKYWALK */

		NECP_FD_UNLOCK(fd_data);

		selthreadclear(&fd_data->si);

		lck_mtx_destroy(&fd_data->fd_lock, &necp_fd_mtx_grp);

		if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
			OSDecrementAtomic(&necp_observer_fd_count);
		} else {
			OSDecrementAtomic(&necp_client_fd_count);
		}

		zfree(necp_client_fd_zone, fd_data);
		fd_data = NULL;

		RB_FOREACH_SAFE(client, _necp_client_tree, &clients_to_close, temp_client) {
			RB_REMOVE(_necp_client_tree, &clients_to_close, client);
			necp_destroy_client(client, pid, true);
		}

		necp_process_defunct_list(&defunct_list);
	}

	return error;
}

/// NECP client utilities

static inline bool
necp_address_is_wildcard(const union necp_sockaddr_union * const addr)
{
	return (addr->sa.sa_family == AF_INET && addr->sin.sin_addr.s_addr == INADDR_ANY) ||
	       (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&addr->sin6.sin6_addr));
}

static int
necp_find_fd_data(struct proc *p, int fd,
    struct fileproc **fpp, struct necp_fd_data **fd_data)
{
	struct fileproc *fp;
	int error = fp_get_ftype(p, fd, DTYPE_NETPOLICY, ENODEV, &fp);

	if (error == 0) {
		*fd_data = (struct necp_fd_data *)fp_get_data(fp);
		*fpp = fp;

		if ((*fd_data)->necp_fd_type != necp_fd_type_client) {
			// Not a client fd, ignore
			fp_drop(p, fd, fp, 0);
			error = EINVAL;
		}
	}
	return error;
}

static void
necp_client_add_nexus_flow(struct necp_client_flow_registration *flow_registration,
    uuid_t nexus_agent,
    uint32_t interface_index,
    uint16_t interface_flags)
{
	struct necp_client_flow *new_flow = mcache_alloc(necp_flow_cache, MCR_SLEEP);
	if (new_flow == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate nexus flow");
		return;
	}

	memset(new_flow, 0, sizeof(*new_flow));

	new_flow->nexus = TRUE;
	uuid_copy(new_flow->u.nexus_agent, nexus_agent);
	new_flow->interface_index = interface_index;
	new_flow->interface_flags = interface_flags;
	new_flow->check_tcp_heuristics = TRUE;

#if SKYWALK
	OSIncrementAtomic(&necp_nexus_flow_count);
#endif /* SKYWALK */

	LIST_INSERT_HEAD(&flow_registration->flow_list, new_flow, flow_chain);

#if SKYWALK
	necp_flow_save_current_interface_details(flow_registration);
#endif /* SKYWALK */
}

static void
necp_client_add_nexus_flow_if_needed(struct necp_client_flow_registration *flow_registration,
    uuid_t nexus_agent,
    uint32_t interface_index)
{
	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (flow->nexus &&
		    uuid_compare(flow->u.nexus_agent, nexus_agent) == 0) {
			return;
		}
	}

	uint16_t interface_flags = 0;
	ifnet_t ifp = NULL;
	ifnet_head_lock_shared();
	if (interface_index != IFSCOPE_NONE && interface_index <= (u_int32_t)if_index) {
		ifp = ifindex2ifnet[interface_index];
		if (ifp != NULL) {
			ifnet_lock_shared(ifp);
			interface_flags = nstat_ifnet_to_flags(ifp);
			ifnet_lock_done(ifp);
		}
	}
	ifnet_head_done();
	necp_client_add_nexus_flow(flow_registration, nexus_agent, interface_index, interface_flags);
}

static struct necp_client_flow *
necp_client_add_interface_flow(struct necp_client_flow_registration *flow_registration,
    uint32_t interface_index)
{
	struct necp_client_flow *new_flow = mcache_alloc(necp_flow_cache, MCR_SLEEP);
	if (new_flow == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate interface flow");
		return NULL;
	}

	memset(new_flow, 0, sizeof(*new_flow));

	// Neither nexus nor socket
	new_flow->interface_index = interface_index;
	new_flow->u.socket_handle = flow_registration->interface_handle;
	new_flow->u.cb = flow_registration->interface_cb;

	OSIncrementAtomic(&necp_if_flow_count);

	LIST_INSERT_HEAD(&flow_registration->flow_list, new_flow, flow_chain);

	return new_flow;
}

static struct necp_client_flow *
necp_client_add_interface_flow_if_needed(struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    uint32_t interface_index)
{
	if (!client->allow_multiple_flows ||
	    interface_index == IFSCOPE_NONE) {
		// Interface not set, or client not allowed to use this mode
		return NULL;
	}

	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (!flow->nexus && !flow->socket && flow->interface_index == interface_index) {
			// Already have the flow
			flow->invalid = FALSE;
			flow->u.socket_handle = flow_registration->interface_handle;
			flow->u.cb = flow_registration->interface_cb;
			return NULL;
		}
	}
	return necp_client_add_interface_flow(flow_registration, interface_index);
}

static void
necp_client_add_interface_option_if_needed(struct necp_client *client,
    uint32_t interface_index,
    uint32_t interface_generation,
    uuid_t *nexus_agent,
    bool network_provider)
{
	if ((interface_index == IFSCOPE_NONE && !network_provider) ||
	    (client->interface_option_count != 0 && !client->allow_multiple_flows)) {
		// Interface not set, or client not allowed to use this mode
		return;
	}

	if (client->interface_option_count >= NECP_CLIENT_MAX_INTERFACE_OPTIONS) {
		// Cannot take any more interface options
		return;
	}

	// Check if already present
	for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
		if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
			struct necp_client_interface_option *option = &client->interface_options[option_i];
			if (option->interface_index == interface_index) {
				if (nexus_agent == NULL) {
					return;
				}
				if (uuid_compare(option->nexus_agent, *nexus_agent) == 0) {
					return;
				}
				if (uuid_is_null(option->nexus_agent)) {
					uuid_copy(option->nexus_agent, *nexus_agent);
					return;
				}
				// If we get to this point, this is a new nexus flow
			}
		} else {
			struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			if (option->interface_index == interface_index) {
				if (nexus_agent == NULL) {
					return;
				}
				if (uuid_compare(option->nexus_agent, *nexus_agent) == 0) {
					return;
				}
				if (uuid_is_null(option->nexus_agent)) {
					uuid_copy(option->nexus_agent, *nexus_agent);
					return;
				}
				// If we get to this point, this is a new nexus flow
			}
		}
	}

	// Add a new entry
	if (client->interface_option_count < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
		// Add to static
		struct necp_client_interface_option *option = &client->interface_options[client->interface_option_count];
		option->interface_index = interface_index;
		option->interface_generation = interface_generation;
		if (nexus_agent != NULL) {
			uuid_copy(option->nexus_agent, *nexus_agent);
		} else {
			uuid_clear(option->nexus_agent);
		}
		client->interface_option_count++;
	} else {
		// Add to extra
		if (client->extra_interface_options == NULL) {
			client->extra_interface_options = (struct necp_client_interface_option *)kalloc_data(
				sizeof(struct necp_client_interface_option) * NECP_CLIENT_INTERFACE_OPTION_EXTRA_COUNT, Z_WAITOK | Z_ZERO);
		}
		if (client->extra_interface_options != NULL) {
			struct necp_client_interface_option *option = &client->extra_interface_options[client->interface_option_count - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			option->interface_index = interface_index;
			option->interface_generation = interface_generation;
			if (nexus_agent != NULL) {
				uuid_copy(option->nexus_agent, *nexus_agent);
			} else {
				uuid_clear(option->nexus_agent);
			}
			client->interface_option_count++;
		}
	}
}

static bool
necp_client_flow_is_viable(proc_t proc, struct necp_client *client,
    struct necp_client_flow *flow)
{
	struct necp_aggregate_result result;
	bool ignore_address = (client->allow_multiple_flows && !flow->nexus && !flow->socket);

	flow->necp_flow_flags = 0;
	int error = necp_application_find_policy_match_internal(proc, client->parameters,
	    (u_int32_t)client->parameters_length,
	    &result, &flow->necp_flow_flags, NULL,
	    flow->interface_index,
	    &flow->local_addr, &flow->remote_addr, NULL, NULL,
	    NULL, ignore_address, true, NULL);

	// Check for blocking agents
	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result.netagents[i])) {
			// Passed end of valid agents
			break;
		}
		if (result.netagent_use_flags[i] & NECP_AGENT_USE_FLAG_REMOVE) {
			// A removed agent, ignore
			continue;
		}
		u_int32_t flags = netagent_get_flags(result.netagents[i]);
		if ((flags & NETAGENT_FLAG_REGISTERED) &&
		    !(flags & NETAGENT_FLAG_VOLUNTARY) &&
		    !(flags & NETAGENT_FLAG_ACTIVE) &&
		    !(flags & NETAGENT_FLAG_SPECIFIC_USE_ONLY)) {
			// A required agent is not active, cause the flow to be marked non-viable
			return false;
		}
	}

	if (flow->interface_index != IFSCOPE_NONE) {
		ifnet_head_lock_shared();

		struct ifnet *ifp = ifindex2ifnet[flow->interface_index];
		if (ifp && ifp->if_delegated.ifp != IFSCOPE_NONE) {
			flow->delegated_interface_index = ifp->if_delegated.ifp->if_index;
		}

		ifnet_head_done();
	}

	return error == 0 &&
	       result.routed_interface_index != IFSCOPE_NONE &&
	       result.routing_result != NECP_KERNEL_POLICY_RESULT_DROP;
}

static void
necp_flow_add_interface_flows(proc_t proc,
    struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    bool send_initial)
{
	// Traverse all interfaces and add a tracking flow if needed
	for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
		if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
			struct necp_client_interface_option *option = &client->interface_options[option_i];
			struct necp_client_flow *flow = necp_client_add_interface_flow_if_needed(client, flow_registration, option->interface_index);
			if (flow != NULL && send_initial) {
				flow->viable = necp_client_flow_is_viable(proc, client, flow);
				if (flow->viable && flow->u.cb) {
					bool viable = flow->viable;
					flow->u.cb(flow_registration->interface_handle, NECP_CLIENT_CBACTION_INITIAL, flow->interface_index, flow->necp_flow_flags, &viable);
					flow->viable = viable;
				}
			}
		} else {
			struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			struct necp_client_flow *flow = necp_client_add_interface_flow_if_needed(client, flow_registration, option->interface_index);
			if (flow != NULL && send_initial) {
				flow->viable = necp_client_flow_is_viable(proc, client, flow);
				if (flow->viable && flow->u.cb) {
					bool viable = flow->viable;
					flow->u.cb(flow_registration->interface_handle, NECP_CLIENT_CBACTION_INITIAL, flow->interface_index, flow->necp_flow_flags, &viable);
					flow->viable = viable;
				}
			}
		}
	}
}

static bool
necp_client_update_flows(proc_t proc,
    struct necp_client *client,
    struct _necp_flow_defunct_list *defunct_list)
{
	NECP_CLIENT_ASSERT_LOCKED(client);

	bool any_client_updated = FALSE;
	struct necp_client_flow *flow = NULL;
	struct necp_client_flow *temp_flow = NULL;
	struct necp_client_flow_registration *flow_registration = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		if (flow_registration->interface_cb != NULL) {
			// Add any interface flows that are not already tracked
			necp_flow_add_interface_flows(proc, client, flow_registration, false);
		}

		LIST_FOREACH_SAFE(flow, &flow_registration->flow_list, flow_chain, temp_flow) {
			bool client_updated = FALSE;

			// Check policy result for flow
			u_short old_delegated_ifindex = flow->delegated_interface_index;

			int old_flags = flow->necp_flow_flags;
			bool viable = necp_client_flow_is_viable(proc, client, flow);

			// TODO: Defunct nexus flows that are blocked by policy

			if (flow->viable != viable) {
				flow->viable = viable;
				client_updated = TRUE;
			}

			if ((old_flags & NECP_CLIENT_RESULT_FLAG_FORCE_UPDATE) !=
			    (flow->necp_flow_flags & NECP_CLIENT_RESULT_FLAG_FORCE_UPDATE)) {
				client_updated = TRUE;
			}

			if (flow->delegated_interface_index != old_delegated_ifindex) {
				client_updated = TRUE;
			}

			if (flow->viable && client_updated && (flow->socket || (!flow->socket && !flow->nexus)) && flow->u.cb) {
				bool flow_viable = flow->viable;
				flow->u.cb(flow->u.socket_handle, NECP_CLIENT_CBACTION_VIABLE, flow->interface_index, flow->necp_flow_flags, &flow_viable);
				flow->viable = flow_viable;
			}

			if (!flow->viable || flow->invalid) {
				if (client_updated && (flow->socket || (!flow->socket && !flow->nexus)) && flow->u.cb) {
					bool flow_viable = flow->viable;
					flow->u.cb(flow->u.socket_handle, NECP_CLIENT_CBACTION_NONVIABLE, flow->interface_index, flow->necp_flow_flags, &flow_viable);
					flow->viable = flow_viable;
				}
				// The callback might change the viable-flag of the
				// flow depending on its policy. Thus, we need to
				// check the flags again after the callback.
			}

#if SKYWALK
			if (defunct_list != NULL) {
				if (flow->invalid && flow->nexus && flow->assigned && !uuid_is_null(flow->u.nexus_agent)) {
					// This is a nexus flow that was assigned, but not found on path
					u_int32_t flags = netagent_get_flags(flow->u.nexus_agent);
					if (!(flags & NETAGENT_FLAG_REGISTERED)) {
						// The agent is no longer registered! Mark defunct.
						necp_defunct_flow_registration(client, flow_registration, defunct_list);
						client_updated = TRUE;
					}
				}
			}
#else /* !SKYWALK */
			(void)defunct_list;
#endif /* !SKYWALK */

			// Handle flows that no longer match
			if (!flow->viable || flow->invalid) {
				// Drop them as long as they aren't assigned data
				if (!flow->nexus && !flow->assigned) {
					if (flow->assigned_results != NULL) {
						kfree_data(flow->assigned_results, flow->assigned_results_length);
						flow->assigned_results = NULL;
						client_updated = TRUE;
					}
					LIST_REMOVE(flow, flow_chain);
#if SKYWALK
					if (flow->nexus) {
						OSDecrementAtomic(&necp_nexus_flow_count);
					} else
#endif /* SKYWALK */
					if (flow->socket) {
						OSDecrementAtomic(&necp_socket_flow_count);
					} else {
						OSDecrementAtomic(&necp_if_flow_count);
					}
					mcache_free(necp_flow_cache, flow);
				}
			}

			any_client_updated |= client_updated;
		}
#if SKYWALK
		necp_flow_save_current_interface_details(flow_registration);
#endif /* SKYWALK */
	}

	return any_client_updated;
}

static void
necp_client_mark_all_nonsocket_flows_as_invalid(struct necp_client *client)
{
	struct necp_client_flow_registration *flow_registration = NULL;
	struct necp_client_flow *flow = NULL;
	RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
		LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
			if (!flow->socket) { // Socket flows are not marked as invalid
				flow->invalid = TRUE;
			}
		}
	}

	// Reset option count every update
	client->interface_option_count = 0;
}

static inline bool
necp_netagent_is_requested(const struct necp_client_parsed_parameters *parameters,
    uuid_t *netagent_uuid)
{
	// Specific use agents only apply when requested
	bool requested = false;
	if (parameters != NULL) {
		// Check required agent UUIDs
		for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
			if (uuid_is_null(parameters->required_netagents[i])) {
				break;
			}
			if (uuid_compare(parameters->required_netagents[i], *netagent_uuid) == 0) {
				requested = true;
				break;
			}
		}

		if (!requested) {
			// Check required agent types
			bool fetched_type = false;
			char netagent_domain[NETAGENT_DOMAINSIZE];
			char netagent_type[NETAGENT_TYPESIZE];
			memset(&netagent_domain, 0, NETAGENT_DOMAINSIZE);
			memset(&netagent_type, 0, NETAGENT_TYPESIZE);

			for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
				if (strlen(parameters->required_netagent_types[i].netagent_domain) == 0 ||
				    strlen(parameters->required_netagent_types[i].netagent_type) == 0) {
					break;
				}

				if (!fetched_type) {
					if (netagent_get_agent_domain_and_type(*netagent_uuid, netagent_domain, netagent_type)) {
						fetched_type = TRUE;
					} else {
						break;
					}
				}

				if ((strlen(parameters->required_netagent_types[i].netagent_domain) == 0 ||
				    strncmp(netagent_domain, parameters->required_netagent_types[i].netagent_domain, NETAGENT_DOMAINSIZE) == 0) &&
				    (strlen(parameters->required_netagent_types[i].netagent_type) == 0 ||
				    strncmp(netagent_type, parameters->required_netagent_types[i].netagent_type, NETAGENT_TYPESIZE) == 0)) {
					requested = true;
					break;
				}
			}
		}

		// Check preferred agent UUIDs
		for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
			if (uuid_is_null(parameters->preferred_netagents[i])) {
				break;
			}
			if (uuid_compare(parameters->preferred_netagents[i], *netagent_uuid) == 0) {
				requested = true;
				break;
			}
		}

		if (!requested) {
			// Check preferred agent types
			bool fetched_type = false;
			char netagent_domain[NETAGENT_DOMAINSIZE];
			char netagent_type[NETAGENT_TYPESIZE];
			memset(&netagent_domain, 0, NETAGENT_DOMAINSIZE);
			memset(&netagent_type, 0, NETAGENT_TYPESIZE);

			for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
				if (strlen(parameters->preferred_netagent_types[i].netagent_domain) == 0 ||
				    strlen(parameters->preferred_netagent_types[i].netagent_type) == 0) {
					break;
				}

				if (!fetched_type) {
					if (netagent_get_agent_domain_and_type(*netagent_uuid, netagent_domain, netagent_type)) {
						fetched_type = TRUE;
					} else {
						break;
					}
				}

				if ((strlen(parameters->preferred_netagent_types[i].netagent_domain) == 0 ||
				    strncmp(netagent_domain, parameters->preferred_netagent_types[i].netagent_domain, NETAGENT_DOMAINSIZE) == 0) &&
				    (strlen(parameters->preferred_netagent_types[i].netagent_type) == 0 ||
				    strncmp(netagent_type, parameters->preferred_netagent_types[i].netagent_type, NETAGENT_TYPESIZE) == 0)) {
					requested = true;
					break;
				}
			}
		}
	}

	return requested;
}

static bool
necp_netagent_applies_to_client(struct necp_client *client,
    const struct necp_client_parsed_parameters *parameters,
    uuid_t *netagent_uuid, bool allow_nexus,
    uint32_t interface_index, uint32_t interface_generation)
{
#pragma unused(interface_index, interface_generation)
	bool applies = FALSE;
	u_int32_t flags = netagent_get_flags(*netagent_uuid);
	if (!(flags & NETAGENT_FLAG_REGISTERED)) {
		// Unregistered agents never apply
		return applies;
	}

	const bool is_nexus_agent = ((flags & NETAGENT_FLAG_NEXUS_PROVIDER) ||
	    (flags & NETAGENT_FLAG_NEXUS_LISTENER) ||
	    (flags & NETAGENT_FLAG_CUSTOM_ETHER_NEXUS) ||
	    (flags & NETAGENT_FLAG_CUSTOM_IP_NEXUS) ||
	    (flags & NETAGENT_FLAG_INTERPOSE_NEXUS));
	if (is_nexus_agent) {
		if (!allow_nexus) {
			// Hide nexus providers unless allowed
			// Direct interfaces and direct policies are allowed to use a nexus
			// Delegate interfaces or re-scoped interfaces are not allowed
			return applies;
		}

		if ((parameters->flags & NECP_CLIENT_PARAMETER_FLAG_CUSTOM_ETHER) &&
		    !(flags & NETAGENT_FLAG_CUSTOM_ETHER_NEXUS)) {
			// Client requested a custom ether nexus, but this nexus isn't one
			return applies;
		}

		if ((parameters->flags & NECP_CLIENT_PARAMETER_FLAG_CUSTOM_IP) &&
		    !(flags & NETAGENT_FLAG_CUSTOM_IP_NEXUS)) {
			// Client requested a custom IP nexus, but this nexus isn't one
			return applies;
		}

		if ((parameters->flags & NECP_CLIENT_PARAMETER_FLAG_INTERPOSE) &&
		    !(flags & NETAGENT_FLAG_INTERPOSE_NEXUS)) {
			// Client requested an interpose nexus, but this nexus isn't one
			return applies;
		}

		if (!(parameters->flags & NECP_CLIENT_PARAMETER_FLAG_CUSTOM_ETHER) &&
		    !(parameters->flags & NECP_CLIENT_PARAMETER_FLAG_CUSTOM_IP) &&
		    !(parameters->flags & NECP_CLIENT_PARAMETER_FLAG_INTERPOSE) &&
		    !(flags & NETAGENT_FLAG_NEXUS_PROVIDER)) {
			// Client requested default parameters, but this nexus isn't generic
			return applies;
		}
	}

	if (uuid_compare(client->failed_trigger_agent.netagent_uuid, *netagent_uuid) == 0) {
		if (client->failed_trigger_agent.generation == netagent_get_generation(*netagent_uuid)) {
			// If this agent was triggered, and failed, and hasn't changed, keep hiding it
			return applies;
		} else {
			// Mismatch generation, clear out old trigger
			uuid_clear(client->failed_trigger_agent.netagent_uuid);
			client->failed_trigger_agent.generation = 0;
		}
	}

	if (flags & NETAGENT_FLAG_SPECIFIC_USE_ONLY) {
		// Specific use agents only apply when requested
		applies = necp_netagent_is_requested(parameters, netagent_uuid);
	} else {
		applies = TRUE;
	}

#if SKYWALK
	// Add nexus agent if it is a nexus, and either is not a listener, or the nexus supports listeners
	if (applies && is_nexus_agent &&
	    !(parameters->flags & NECP_CLIENT_PARAMETER_FLAG_BROWSE) &&     // Don't add for browse paths
	    ((flags & NETAGENT_FLAG_NEXUS_LISTENER) || !(parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER))) {
		necp_client_add_interface_option_if_needed(client, interface_index,
		    interface_generation, netagent_uuid,
		    (flags & NETAGENT_FLAG_NETWORK_PROVIDER));
	}
#endif /* SKYWALK */

	return applies;
}

static void
necp_client_add_agent_interface_options(struct necp_client *client,
    const struct necp_client_parsed_parameters *parsed_parameters,
    ifnet_t ifp)
{
	if (ifp != NULL && ifp->if_agentids != NULL) {
		for (u_int32_t i = 0; i < ifp->if_agentcount; i++) {
			if (uuid_is_null(ifp->if_agentids[i])) {
				continue;
			}
			// Relies on the side effect that nexus agents that apply will create flows
			(void)necp_netagent_applies_to_client(client, parsed_parameters, &ifp->if_agentids[i], TRUE,
			    ifp->if_index, ifnet_get_generation(ifp));
		}
	}
}

static void
necp_client_add_browse_interface_options(struct necp_client *client,
    const struct necp_client_parsed_parameters *parsed_parameters,
    ifnet_t ifp)
{
	if (ifp != NULL && ifp->if_agentids != NULL) {
		for (u_int32_t i = 0; i < ifp->if_agentcount; i++) {
			if (uuid_is_null(ifp->if_agentids[i])) {
				continue;
			}

			u_int32_t flags = netagent_get_flags(ifp->if_agentids[i]);
			if ((flags & NETAGENT_FLAG_REGISTERED) &&
			    (flags & NETAGENT_FLAG_ACTIVE) &&
			    (flags & NETAGENT_FLAG_SUPPORTS_BROWSE) &&
			    (!(flags & NETAGENT_FLAG_SPECIFIC_USE_ONLY) ||
			    necp_netagent_is_requested(parsed_parameters, &ifp->if_agentids[i]))) {
				necp_client_add_interface_option_if_needed(client, ifp->if_index, ifnet_get_generation(ifp), &ifp->if_agentids[i], (flags & NETAGENT_FLAG_NETWORK_PROVIDER));

				// Finding one is enough
				break;
			}
		}
	}
}

static inline bool
necp_client_address_is_valid(struct sockaddr *address)
{
	if (address->sa_family == AF_INET) {
		return address->sa_len == sizeof(struct sockaddr_in);
	} else if (address->sa_family == AF_INET6) {
		return address->sa_len == sizeof(struct sockaddr_in6);
	} else {
		return FALSE;
	}
}

static inline bool
necp_client_endpoint_is_unspecified(struct necp_client_endpoint *endpoint)
{
	if (necp_client_address_is_valid(&endpoint->u.sa)) {
		if (endpoint->u.sa.sa_family == AF_INET) {
			return endpoint->u.sin.sin_addr.s_addr == INADDR_ANY;
		} else if (endpoint->u.sa.sa_family == AF_INET6) {
			return IN6_IS_ADDR_UNSPECIFIED(&endpoint->u.sin6.sin6_addr);
		} else {
			return TRUE;
		}
	} else {
		return TRUE;
	}
}

#if SKYWALK
static void
necp_client_update_local_port_parameters(u_int8_t *parameters,
    u_int32_t parameters_size,
    uint16_t local_port)
{
	size_t offset = 0;
	while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
			// If the length is larger than what can fit in the remaining parameters size, bail
			NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
			break;
		}

		if (length > 0) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_PARAMETER_LOCAL_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							if (address_struct->address.sa.sa_family == AF_INET) {
								address_struct->address.sin.sin_port = local_port;
							} else if (address_struct->address.sa.sa_family == AF_INET6) {
								address_struct->address.sin6.sin6_port = local_port;
							}
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_LOCAL_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (necp_client_address_is_valid(&endpoint->u.sa)) {
							if (endpoint->u.sa.sa_family == AF_INET) {
								endpoint->u.sin.sin_port = local_port;
							} else if (endpoint->u.sa.sa_family == AF_INET6) {
								endpoint->u.sin6.sin6_port = local_port;
							}
						}
					}
					break;
				}
				default: {
					break;
				}
				}
			}
		}

		offset += sizeof(struct necp_tlv_header) + length;
	}
}
#endif /* !SKYWALK */

#define NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH 253

static void
necp_client_trace_parameter_parsing(struct necp_client *client, u_int8_t type, u_int8_t *value, u_int32_t length)
{
	uint64_t num = 0;
	uint16_t shortBuf;
	uint32_t intBuf;
	char buffer[NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH + 1];

	if (value != NULL && length > 0) {
		switch (length) {
		case 1:
			num = *value;
			break;
		case 2:
			memcpy(&shortBuf, value, sizeof(shortBuf));
			num = shortBuf;
			break;
		case 4:
			memcpy(&intBuf, value, sizeof(intBuf));
			num = intBuf;
			break;
		case 8:
			memcpy(&num, value, sizeof(num));
			break;
		default:
			num = 0;
			break;
		}
		int len = NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH < length ? NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH : length;
		memcpy(buffer, value, len);
		buffer[len] = 0;
		NECP_CLIENT_PARAMS_LOG(client, "Parsing param - type %d length %d value <%llu (%llX)> %s", type, length, num, num, buffer);
	} else {
		NECP_CLIENT_PARAMS_LOG(client, "Parsing param - type %d length %d", type, length);
	}
}

static void
necp_client_trace_parsed_parameters(struct necp_client *client, struct necp_client_parsed_parameters *parsed_parameters)
{
	int i;
	char local_buffer[64] = { };
	char remote_buffer[64] = { };
	uuid_string_t uuid_str = { };
	uuid_unparse_lower(parsed_parameters->effective_uuid, uuid_str);

	switch (parsed_parameters->local_addr.sa.sa_family) {
	case AF_INET:
		if (parsed_parameters->local_addr.sa.sa_len == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *addr = &parsed_parameters->local_addr.sin;
			inet_ntop(AF_INET, &(addr->sin_addr), local_buffer, sizeof(local_buffer));
		}
		break;
	case AF_INET6:
		if (parsed_parameters->local_addr.sa.sa_len == sizeof(struct sockaddr_in6)) {
			struct sockaddr_in6 *addr6 = &parsed_parameters->local_addr.sin6;
			inet_ntop(AF_INET6, &(addr6->sin6_addr), local_buffer, sizeof(local_buffer));
		}
		break;
	default:
		break;
	}

	switch (parsed_parameters->remote_addr.sa.sa_family) {
	case AF_INET:
		if (parsed_parameters->remote_addr.sa.sa_len == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *addr = &parsed_parameters->remote_addr.sin;
			inet_ntop(AF_INET, &(addr->sin_addr), remote_buffer, sizeof(remote_buffer));
		}
		break;
	case AF_INET6:
		if (parsed_parameters->remote_addr.sa.sa_len == sizeof(struct sockaddr_in6)) {
			struct sockaddr_in6 *addr6 = &parsed_parameters->remote_addr.sin6;
			inet_ntop(AF_INET6, &(addr6->sin6_addr), remote_buffer, sizeof(remote_buffer));
		}
		break;
	default:
		break;
	}

	NECP_CLIENT_PARAMS_LOG(client, "Parsed params - valid_fields %X flags %X delegated_upid %llu local_addr %s remote_addr %s "
	    "required_interface_index %u required_interface_type %d local_address_preference %d "
	    "ip_protocol %d transport_protocol %d ethertype %d effective_pid %d effective_uuid %s traffic_class %d",
	    parsed_parameters->valid_fields,
	    parsed_parameters->flags,
	    parsed_parameters->delegated_upid,
	    local_buffer, remote_buffer,
	    parsed_parameters->required_interface_index,
	    parsed_parameters->required_interface_type,
	    parsed_parameters->local_address_preference,
	    parsed_parameters->ip_protocol,
	    parsed_parameters->transport_protocol,
	    parsed_parameters->ethertype,
	    parsed_parameters->effective_pid,
	    uuid_str,
	    parsed_parameters->traffic_class);

	NECP_CLIENT_PARAMS_LOG(client, "Parsed params - tracker flags <known-tracker %X> <non-app-initiated %X> <silent %X> <app-approved %X>",
	    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_KNOWN_TRACKER,
	    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_NON_APP_INITIATED,
	    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_SILENT,
	    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_APPROVED_APP_DOMAIN);

	for (i = 0; i < NECP_MAX_INTERFACE_PARAMETERS && parsed_parameters->prohibited_interfaces[i][0]; i++) {
		NECP_CLIENT_PARAMS_LOG(client, "Parsed prohibited_interfaces[%d] <%s>", i, parsed_parameters->prohibited_interfaces[i]);
	}

	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && parsed_parameters->required_netagent_types[i].netagent_domain[0]; i++) {
		NECP_CLIENT_PARAMS_LOG(client, "Parsed required_netagent_types[%d] <%s> <%s>", i,
		    parsed_parameters->required_netagent_types[i].netagent_domain,
		    parsed_parameters->required_netagent_types[i].netagent_type);
	}
	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && parsed_parameters->prohibited_netagent_types[i].netagent_domain[0]; i++) {
		NECP_CLIENT_PARAMS_LOG(client, "Parsed prohibited_netagent_types[%d] <%s> <%s>", i,
		    parsed_parameters->prohibited_netagent_types[i].netagent_domain,
		    parsed_parameters->prohibited_netagent_types[i].netagent_type);
	}
	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && parsed_parameters->preferred_netagent_types[i].netagent_domain[0]; i++) {
		NECP_CLIENT_PARAMS_LOG(client, "Parsed preferred_netagent_types[%d] <%s> <%s>", i,
		    parsed_parameters->preferred_netagent_types[i].netagent_domain,
		    parsed_parameters->preferred_netagent_types[i].netagent_type);
	}
	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && parsed_parameters->avoided_netagent_types[i].netagent_domain[0]; i++) {
		NECP_CLIENT_PARAMS_LOG(client, "Parsed avoided_netagent_types[%d] <%s> <%s>", i,
		    parsed_parameters->avoided_netagent_types[i].netagent_domain,
		    parsed_parameters->avoided_netagent_types[i].netagent_type);
	}

	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && !uuid_is_null(parsed_parameters->required_netagents[i]); i++) {
		uuid_unparse_lower(parsed_parameters->required_netagents[i], uuid_str);
		NECP_CLIENT_PARAMS_LOG(client, "Parsed required_netagents[%d] <%s>", i, uuid_str);
	}
	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && !uuid_is_null(parsed_parameters->prohibited_netagents[i]); i++) {
		uuid_unparse_lower(parsed_parameters->prohibited_netagents[i], uuid_str);
		NECP_CLIENT_PARAMS_LOG(client, "Parsed prohibited_netagents[%d] <%s>", i, uuid_str);
	}
	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && !uuid_is_null(parsed_parameters->preferred_netagents[i]); i++) {
		uuid_unparse_lower(parsed_parameters->preferred_netagents[i], uuid_str);
		NECP_CLIENT_PARAMS_LOG(client, "Parsed preferred_netagents[%d] <%s>", i, uuid_str);
	}
	for (i = 0; i < NECP_MAX_AGENT_PARAMETERS && !uuid_is_null(parsed_parameters->avoided_netagents[i]); i++) {
		uuid_unparse_lower(parsed_parameters->avoided_netagents[i], uuid_str);
		NECP_CLIENT_PARAMS_LOG(client, "Parsed avoided_netagents[%d] <%s>", i, uuid_str);
	}
}

static int
necp_client_parse_parameters(struct necp_client *client, u_int8_t *parameters,
    u_int32_t parameters_size,
    struct necp_client_parsed_parameters *parsed_parameters)
{
	int error = 0;
	size_t offset = 0;

	u_int32_t num_prohibited_interfaces = 0;
	u_int32_t num_prohibited_interface_types = 0;
	u_int32_t num_required_agents = 0;
	u_int32_t num_prohibited_agents = 0;
	u_int32_t num_preferred_agents = 0;
	u_int32_t num_avoided_agents = 0;
	u_int32_t num_required_agent_types = 0;
	u_int32_t num_prohibited_agent_types = 0;
	u_int32_t num_preferred_agent_types = 0;
	u_int32_t num_avoided_agent_types = 0;
	u_int8_t *resolver_tag = NULL;
	u_int32_t resolver_tag_length = 0;
	u_int8_t *client_hostname = NULL;
	u_int32_t hostname_length = 0;
	uuid_t parent_id = {};

	if (parsed_parameters == NULL) {
		return EINVAL;
	}

	memset(parsed_parameters, 0, sizeof(struct necp_client_parsed_parameters));

	while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
			// If the length is larger than what can fit in the remaining parameters size, bail
			NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
			break;
		}

		if (length > 0) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_PARAMETER_BOUND_INTERFACE: {
					if (length <= IFXNAMSIZ && length > 0) {
						ifnet_t bound_interface = NULL;
						char interface_name[IFXNAMSIZ];
						memcpy(interface_name, value, length);
						interface_name[length - 1] = 0;         // Make sure the string is NULL terminated
						if (ifnet_find_by_name(interface_name, &bound_interface) == 0) {
							parsed_parameters->required_interface_index = bound_interface->if_index;
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF;
							ifnet_release(bound_interface);
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_LOCAL_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							memcpy(&parsed_parameters->local_addr, &address_struct->address, sizeof(address_struct->address));
							if (!necp_address_is_wildcard(&parsed_parameters->local_addr)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR;
							}
							if ((parsed_parameters->local_addr.sa.sa_family == AF_INET && parsed_parameters->local_addr.sin.sin_port) ||
							    (parsed_parameters->local_addr.sa.sa_family == AF_INET6 && parsed_parameters->local_addr.sin6.sin6_port)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_PORT;
							}
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_LOCAL_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(&parsed_parameters->local_addr, &endpoint->u.sa, sizeof(union necp_sockaddr_union));
							if (!necp_address_is_wildcard(&parsed_parameters->local_addr)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR;
							}
							if ((parsed_parameters->local_addr.sa.sa_family == AF_INET && parsed_parameters->local_addr.sin.sin_port) ||
							    (parsed_parameters->local_addr.sa.sa_family == AF_INET6 && parsed_parameters->local_addr.sin6.sin6_port)) {
								parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_PORT;
							}
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							memcpy(&parsed_parameters->remote_addr, &address_struct->address, sizeof(address_struct->address));
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REMOTE_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(&parsed_parameters->remote_addr, &endpoint->u.sa, sizeof(union necp_sockaddr_union));
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_INTERFACE: {
					if (num_prohibited_interfaces >= NECP_MAX_INTERFACE_PARAMETERS) {
						break;
					}
					if (length <= IFXNAMSIZ && length > 0) {
						memcpy(parsed_parameters->prohibited_interfaces[num_prohibited_interfaces], value, length);
						parsed_parameters->prohibited_interfaces[num_prohibited_interfaces][length - 1] = 0;         // Make sure the string is NULL terminated
						num_prohibited_interfaces++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REQUIRE_IF_TYPE: {
					if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) {
						break;
					}
					if (length >= sizeof(u_int8_t)) {
						memcpy(&parsed_parameters->required_interface_type, value, sizeof(u_int8_t));
						if (parsed_parameters->required_interface_type) {
							parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_IF_TYPE: {
					if (num_prohibited_interface_types >= NECP_MAX_INTERFACE_PARAMETERS) {
						break;
					}
					if (length >= sizeof(u_int8_t)) {
						memcpy(&parsed_parameters->prohibited_interface_types[num_prohibited_interface_types], value, sizeof(u_int8_t));
						num_prohibited_interface_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REQUIRE_AGENT: {
					if (num_required_agents >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->required_netagents[num_required_agents], value, sizeof(uuid_t));
						num_required_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_AGENT: {
					if (num_prohibited_agents >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->prohibited_netagents[num_prohibited_agents], value, sizeof(uuid_t));
						num_prohibited_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PREFER_AGENT: {
					if (num_preferred_agents >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->preferred_netagents[num_preferred_agents], value, sizeof(uuid_t));
						num_preferred_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_AVOID_AGENT: {
					if (num_avoided_agents >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(uuid_t)) {
						memcpy(&parsed_parameters->avoided_netagents[num_avoided_agents], value, sizeof(uuid_t));
						num_avoided_agents++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_REQUIRE_AGENT_TYPE: {
					if (num_required_agent_types >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->required_netagent_types[num_required_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_required_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PROHIBIT_AGENT_TYPE: {
					if (num_prohibited_agent_types >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->prohibited_netagent_types[num_prohibited_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_prohibited_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PREFER_AGENT_TYPE: {
					if (num_preferred_agent_types >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->preferred_netagent_types[num_preferred_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_preferred_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_AVOID_AGENT_TYPE: {
					if (num_avoided_agent_types >= NECP_MAX_AGENT_PARAMETERS) {
						break;
					}
					if (length >= sizeof(struct necp_client_parameter_netagent_type)) {
						memcpy(&parsed_parameters->avoided_netagent_types[num_avoided_agent_types], value, sizeof(struct necp_client_parameter_netagent_type));
						num_avoided_agent_types++;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_FLAGS: {
					if (length >= sizeof(u_int32_t)) {
						memcpy(&parsed_parameters->flags, value, sizeof(parsed_parameters->flags));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_FLAGS;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_IP_PROTOCOL: {
					if (length == sizeof(u_int16_t)) {
						u_int16_t large_ip_protocol = 0;
						memcpy(&large_ip_protocol, value, sizeof(large_ip_protocol));
						parsed_parameters->ip_protocol = (u_int8_t)large_ip_protocol;
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_IP_PROTOCOL;
					} else if (length >= sizeof(parsed_parameters->ip_protocol)) {
						memcpy(&parsed_parameters->ip_protocol, value, sizeof(parsed_parameters->ip_protocol));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_IP_PROTOCOL;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_TRANSPORT_PROTOCOL: {
					if (length >= sizeof(parsed_parameters->transport_protocol)) {
						memcpy(&parsed_parameters->transport_protocol, value, sizeof(parsed_parameters->transport_protocol));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_TRANSPORT_PROTOCOL;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PID: {
					if (length >= sizeof(parsed_parameters->effective_pid)) {
						memcpy(&parsed_parameters->effective_pid, value, sizeof(parsed_parameters->effective_pid));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_DELEGATED_UPID: {
					if (length >= sizeof(parsed_parameters->delegated_upid)) {
						memcpy(&parsed_parameters->delegated_upid, value, sizeof(parsed_parameters->delegated_upid));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_DELEGATED_UPID;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_ETHERTYPE: {
					if (length >= sizeof(parsed_parameters->ethertype)) {
						memcpy(&parsed_parameters->ethertype, value, sizeof(parsed_parameters->ethertype));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_ETHERTYPE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_APPLICATION: {
					if (length >= sizeof(parsed_parameters->effective_uuid)) {
						memcpy(&parsed_parameters->effective_uuid, value, sizeof(parsed_parameters->effective_uuid));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_UUID;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_TRAFFIC_CLASS: {
					if (length >= sizeof(parsed_parameters->traffic_class)) {
						memcpy(&parsed_parameters->traffic_class, value, sizeof(parsed_parameters->traffic_class));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_TRAFFIC_CLASS;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_RESOLVER_TAG: {
					if (length > 0) {
						resolver_tag = (u_int8_t *)value;
						resolver_tag_length = length;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_DOMAIN: {
					if (length > 0) {
						client_hostname = (u_int8_t *)value;
						hostname_length = length;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PARENT_ID: {
					if (length == sizeof(parent_id)) {
						uuid_copy(parent_id, value);
						memcpy(&parsed_parameters->parent_uuid, value, sizeof(parsed_parameters->parent_uuid));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_PARENT_UUID;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_LOCAL_ADDRESS_PREFERENCE: {
					if (length >= sizeof(parsed_parameters->local_address_preference)) {
						memcpy(&parsed_parameters->local_address_preference, value, sizeof(parsed_parameters->local_address_preference));
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR_PREFERENCE;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_ATTRIBUTED_BUNDLE_IDENTIFIER: {
					if (length > 0) {
						parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_ATTRIBUTED_BUNDLE_IDENTIFIER;
					}
					break;
				}
				default: {
					break;
				}
				}
			}

			if (NECP_ENABLE_CLIENT_TRACE(NECP_CLIENT_TRACE_LEVEL_PARAMS)) {
				necp_client_trace_parameter_parsing(client, type, value, length);
			}
		}

		offset += sizeof(struct necp_tlv_header) + length;
	}

	if (resolver_tag != NULL) {
		union necp_sockaddr_union remote_addr;
		memcpy(&remote_addr, &parsed_parameters->remote_addr, sizeof(remote_addr));
		remote_addr.sin.sin_port = 0;
		const bool validated = necp_validate_resolver_answer(parent_id,
		    client_hostname, hostname_length,
		    (u_int8_t *)&remote_addr, sizeof(remote_addr),
		    resolver_tag, resolver_tag_length);
		if (!validated) {
			error = EAUTH;
			NECPLOG(LOG_ERR, "Failed to validate answer for hostname %s", client_hostname);
		}
	}

	// Log if it is a known tracker
	if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_KNOWN_TRACKER && client) {
		NECP_CLIENT_TRACKER_LOG(client->proc_pid, "Parsing tracker flags - known-tracker %X non-app-initiated %X silent %X approved-app-domain %X",
		    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_KNOWN_TRACKER,
		    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_NON_APP_INITIATED,
		    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_SILENT,
		    parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_APPROVED_APP_DOMAIN);
	}

	if (NECP_ENABLE_CLIENT_TRACE(NECP_CLIENT_TRACE_LEVEL_PARAMS)) {
		necp_client_trace_parsed_parameters(client, parsed_parameters);
	}

	return error;
}

static int
necp_client_parse_result(u_int8_t *result,
    u_int32_t result_size,
    union necp_sockaddr_union *local_address,
    union necp_sockaddr_union *remote_address,
    void **flow_stats)
{
#pragma unused(flow_stats)
	int error = 0;
	size_t offset = 0;

	while ((offset + sizeof(struct necp_tlv_header)) <= result_size) {
		u_int8_t type = necp_buffer_get_tlv_type(result, offset);
		u_int32_t length = necp_buffer_get_tlv_length(result, offset);

		if (length > 0 && (offset + sizeof(struct necp_tlv_header) + length) <= result_size) {
			u_int8_t *value = necp_buffer_get_tlv_value(result, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_RESULT_LOCAL_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (local_address != NULL && necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(local_address, &endpoint->u.sa, endpoint->u.sa.sa_len);
						}
					}
					break;
				}
				case NECP_CLIENT_RESULT_REMOTE_ENDPOINT: {
					if (length >= sizeof(struct necp_client_endpoint)) {
						struct necp_client_endpoint *endpoint = (struct necp_client_endpoint *)(void *)value;
						if (remote_address != NULL && necp_client_address_is_valid(&endpoint->u.sa)) {
							memcpy(remote_address, &endpoint->u.sa, endpoint->u.sa.sa_len);
						}
					}
					break;
				}
#if SKYWALK
				case NECP_CLIENT_RESULT_NEXUS_FLOW_STATS: {
					// this TLV contains flow_stats pointer which is refcnt'ed.
					if (length >= sizeof(struct sk_stats_flow *)) {
						struct flow_stats *fs = *(void **)(void *)value;
						if (flow_stats != NULL) {
							// transfer the refcnt to flow_stats pointer
							*flow_stats = fs;
						} else {
							// otherwise, release the refcnt
							VERIFY(fs != NULL);
							flow_stats_release(fs);
						}
						memset(value, 0, sizeof(struct flow_stats*));         // nullify TLV always
					}
					break;
				}
#endif /* SKYWALK */
				default: {
					break;
				}
				}
			}
		}

		offset += sizeof(struct necp_tlv_header) + length;
	}

	return error;
}

static struct necp_client_flow_registration *
necp_client_create_flow_registration(struct necp_fd_data *fd_data, struct necp_client *client)
{
	NECP_FD_ASSERT_LOCKED(fd_data);
	NECP_CLIENT_ASSERT_LOCKED(client);

	struct necp_client_flow_registration *new_registration = mcache_alloc(necp_flow_registration_cache, MCR_SLEEP);
	if (new_registration == NULL) {
		return NULL;
	}

	memset(new_registration, 0, sizeof(*new_registration));

	new_registration->last_interface_details = combine_interface_details(IFSCOPE_NONE, NSTAT_IFNET_IS_UNKNOWN_TYPE);

	necp_generate_client_id(new_registration->registration_id, true);
	LIST_INIT(&new_registration->flow_list);

	// Add registration to client list
	RB_INSERT(_necp_client_flow_tree, &client->flow_registrations, new_registration);

	// Add registration to fd list
	RB_INSERT(_necp_fd_flow_tree, &fd_data->flows, new_registration);

	// Add registration to global tree for lookup
	NECP_FLOW_TREE_LOCK_EXCLUSIVE();
	RB_INSERT(_necp_client_flow_global_tree, &necp_client_flow_global_tree, new_registration);
	NECP_FLOW_TREE_UNLOCK();

	new_registration->client = client;

#if SKYWALK
	{
		// The uuid caching here is something of a hack, but saves a dynamic lookup with attendant lock hierarchy issues
		uint64_t stats_event_type = (uuid_is_null(client->latest_flow_registration_id)) ? NSTAT_EVENT_SRC_FLOW_UUID_ASSIGNED : NSTAT_EVENT_SRC_FLOW_UUID_CHANGED;
		uuid_copy(client->latest_flow_registration_id, new_registration->registration_id);

		// With the flow uuid known, push a new statistics update to ensure the uuid gets known by any clients before the flow can close
		if (client->nstat_context != NULL) {
			nstat_provider_stats_event(client->nstat_context, stats_event_type);
		}
	}
#endif /* !SKYWALK */

	// Start out assuming there is nothing to read from the flow
	new_registration->flow_result_read = true;

	return new_registration;
}

static void
necp_client_add_socket_flow(struct necp_client_flow_registration *flow_registration,
    struct inpcb *inp)
{
	struct necp_client_flow *new_flow = mcache_alloc(necp_flow_cache, MCR_SLEEP);
	if (new_flow == NULL) {
		NECPLOG0(LOG_ERR, "Failed to allocate socket flow");
		return;
	}

	memset(new_flow, 0, sizeof(*new_flow));

	new_flow->socket = TRUE;
	new_flow->u.socket_handle = inp;
	new_flow->u.cb = inp->necp_cb;

	OSIncrementAtomic(&necp_socket_flow_count);

	LIST_INSERT_HEAD(&flow_registration->flow_list, new_flow, flow_chain);
}

static int
necp_client_register_socket_inner(pid_t pid, uuid_t client_id, struct inpcb *inp, bool is_listener)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			if (!pid || client->proc_pid == pid) {
				if (is_listener) {
					found_client = TRUE;
#if SKYWALK
					// Check netns token for registration
					if (!NETNS_TOKEN_VALID(&client->port_reservation)) {
						error = EINVAL;
					}
#endif /* !SKYWALK */
				} else {
					// Find client flow and assign from socket
					struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
					if (flow_registration != NULL) {
						// Found the right client and flow registration, add a new flow
						found_client = TRUE;
						necp_client_add_socket_flow(flow_registration, inp);
					} else if (RB_EMPTY(&client->flow_registrations) && !necp_client_id_is_flow(client_id)) {
						// No flows yet on this client, add a new registration
						flow_registration = necp_client_create_flow_registration(client_fd, client);
						if (flow_registration == NULL) {
							error = ENOMEM;
						} else {
							// Add a new flow
							found_client = TRUE;
							necp_client_add_socket_flow(flow_registration, inp);
						}
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	} else {
		// Count the sockets that have the NECP client UUID set
		struct socket *so = inp->inp_socket;
		if (!(so->so_flags1 & SOF1_HAS_NECP_CLIENT_UUID)) {
			so->so_flags1 |= SOF1_HAS_NECP_CLIENT_UUID;
			INC_ATOMIC_INT64_LIM(net_api_stats.nas_socket_necp_clientuuid_total);
		}
	}

	return error;
}

int
necp_client_register_socket_flow(pid_t pid, uuid_t client_id, struct inpcb *inp)
{
	return necp_client_register_socket_inner(pid, client_id, inp, false);
}

int
necp_client_register_socket_listener(pid_t pid, uuid_t client_id, struct inpcb *inp)
{
	return necp_client_register_socket_inner(pid, client_id, inp, true);
}

#if SKYWALK
int
necp_client_get_netns_flow_info(uuid_t client_id, struct ns_flow_info *flow_info)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			found_client = TRUE;
			if (!NETNS_TOKEN_VALID(&client->port_reservation)) {
				error = EINVAL;
			} else {
				error = netns_get_flow_info(&client->port_reservation, flow_info);
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	}

	return error;
}
#endif /* !SKYWALK */

static void
necp_client_add_multipath_interface_flows(struct necp_client_flow_registration *flow_registration,
    struct necp_client *client,
    struct mppcb *mpp)
{
	flow_registration->interface_handle = mpp;
	flow_registration->interface_cb = mpp->necp_cb;

	proc_t proc = proc_find(client->proc_pid);
	if (proc == PROC_NULL) {
		return;
	}

	// Traverse all interfaces and add a tracking flow if needed
	necp_flow_add_interface_flows(proc, client, flow_registration, true);

	proc_rele(proc);
	proc = PROC_NULL;
}

int
necp_client_register_multipath_cb(pid_t pid, uuid_t client_id, struct mppcb *mpp)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			if (!pid || client->proc_pid == pid) {
				struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
				if (flow_registration != NULL) {
					// Found the right client and flow registration, add a new flow
					found_client = TRUE;
					necp_client_add_multipath_interface_flows(flow_registration, client, mpp);
				} else if (RB_EMPTY(&client->flow_registrations) && !necp_client_id_is_flow(client_id)) {
					// No flows yet on this client, add a new registration
					flow_registration = necp_client_create_flow_registration(client_fd, client);
					if (flow_registration == NULL) {
						error = ENOMEM;
					} else {
						// Add a new flow
						found_client = TRUE;
						necp_client_add_multipath_interface_flows(flow_registration, client, mpp);
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client && error == 0) {
		error = ENOENT;
	}

	return error;
}

#define NETAGENT_DOMAIN_RADIO_MANAGER   "WirelessRadioManager"
#define NETAGENT_TYPE_RADIO_MANAGER     "WirelessRadioManager:BB Manager"

static int
necp_client_lookup_bb_radio_manager(struct necp_client *client,
    uuid_t netagent_uuid)
{
	char netagent_domain[NETAGENT_DOMAINSIZE];
	char netagent_type[NETAGENT_TYPESIZE];
	struct necp_aggregate_result result;
	proc_t proc;
	int error;

	proc = proc_find(client->proc_pid);
	if (proc == PROC_NULL) {
		return ESRCH;
	}

	error = necp_application_find_policy_match_internal(proc, client->parameters, (u_int32_t)client->parameters_length,
	    &result, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, true, true, NULL);

	proc_rele(proc);
	proc = PROC_NULL;

	if (error) {
		return error;
	}

	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result.netagents[i])) {
			// Passed end of valid agents
			break;
		}

		memset(&netagent_domain, 0, NETAGENT_DOMAINSIZE);
		memset(&netagent_type, 0, NETAGENT_TYPESIZE);
		if (netagent_get_agent_domain_and_type(result.netagents[i], netagent_domain, netagent_type) == FALSE) {
			continue;
		}

		if (strncmp(netagent_domain, NETAGENT_DOMAIN_RADIO_MANAGER, NETAGENT_DOMAINSIZE) != 0) {
			continue;
		}

		if (strncmp(netagent_type, NETAGENT_TYPE_RADIO_MANAGER, NETAGENT_TYPESIZE) != 0) {
			continue;
		}

		uuid_copy(netagent_uuid, result.netagents[i]);

		break;
	}

	return 0;
}

static int
necp_client_assert_bb_radio_manager_common(struct necp_client *client, bool assert)
{
	uuid_t netagent_uuid;
	uint8_t assert_type;
	int error;

	error = necp_client_lookup_bb_radio_manager(client, netagent_uuid);
	if (error) {
		NECPLOG0(LOG_ERR, "BB radio manager agent not found");
		return error;
	}

	// Before unasserting, verify that the assertion was already taken
	if (assert == FALSE) {
		assert_type = NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT;

		if (!necp_client_remove_assertion(client, netagent_uuid)) {
			return EINVAL;
		}
	} else {
		assert_type = NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT;
	}

	error = netagent_client_message(netagent_uuid, client->client_id, client->proc_pid, client->agent_handle, assert_type);
	if (error) {
		NECPLOG0(LOG_ERR, "netagent_client_message failed");
		return error;
	}

	// Only save the assertion if the action succeeded
	if (assert == TRUE) {
		necp_client_add_assertion(client, netagent_uuid);
	}

	return 0;
}

int
necp_client_assert_bb_radio_manager(uuid_t client_id, bool assert)
{
	struct necp_client *client;
	int error = 0;

	NECP_CLIENT_TREE_LOCK_SHARED();

	client = necp_find_client_and_lock(client_id);

	if (client) {
		// Found the right client!
		error = necp_client_assert_bb_radio_manager_common(client, assert);

		NECP_CLIENT_UNLOCK(client);
	} else {
		NECPLOG0(LOG_ERR, "Couldn't find client");
		error = ENOENT;
	}

	NECP_CLIENT_TREE_UNLOCK();

	return error;
}

static int
necp_client_unregister_socket_flow(uuid_t client_id, void *handle)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);

		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;

				// Remove flow assignment
				struct necp_client_flow *search_flow = NULL;
				struct necp_client_flow *temp_flow = NULL;
				LIST_FOREACH_SAFE(search_flow, &flow_registration->flow_list, flow_chain, temp_flow) {
					if (search_flow->socket && search_flow->u.socket_handle == handle) {
						if (search_flow->assigned_results != NULL) {
							kfree_data(search_flow->assigned_results, search_flow->assigned_results_length);
							search_flow->assigned_results = NULL;
						}
						client_updated = TRUE;
						flow_registration->flow_result_read = FALSE;
						LIST_REMOVE(search_flow, flow_chain);
						OSDecrementAtomic(&necp_socket_flow_count);
						mcache_free(necp_flow_cache, search_flow);
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}

		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}
		NECP_FD_UNLOCK(client_fd);

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	}

	return error;
}

static int
necp_client_unregister_multipath_cb(uuid_t client_id, void *handle)
{
	int error = 0;
	bool found_client = FALSE;

	NECP_CLIENT_TREE_LOCK_SHARED();

	struct necp_client *client = necp_find_client_and_lock(client_id);
	if (client != NULL) {
		struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
		if (flow_registration != NULL) {
			// Found the right client and flow!
			found_client = TRUE;

			// Remove flow assignment
			struct necp_client_flow *search_flow = NULL;
			struct necp_client_flow *temp_flow = NULL;
			LIST_FOREACH_SAFE(search_flow, &flow_registration->flow_list, flow_chain, temp_flow) {
				if (!search_flow->socket && !search_flow->nexus &&
				    search_flow->u.socket_handle == handle) {
					search_flow->u.socket_handle = NULL;
					search_flow->u.cb = NULL;
				}
			}

			flow_registration->interface_handle = NULL;
			flow_registration->interface_cb = NULL;
		}

		NECP_CLIENT_UNLOCK(client);
	}

	NECP_CLIENT_TREE_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	}

	return error;
}

int
necp_client_assign_from_socket(pid_t pid, uuid_t client_id, struct inpcb *inp)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		if (pid && client_fd->proc_pid != pid) {
			continue;
		}

		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);

		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration == NULL && RB_EMPTY(&client->flow_registrations) && !necp_client_id_is_flow(client_id)) {
				// No flows yet on this client, add a new registration
				flow_registration = necp_client_create_flow_registration(client_fd, client);
				if (flow_registration == NULL) {
					error = ENOMEM;
				}
			}
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;

				struct necp_client_flow *flow = NULL;
				LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
					if (flow->socket && flow->u.socket_handle == inp) {
						// Release prior results and route
						if (flow->assigned_results != NULL) {
							kfree_data(flow->assigned_results, flow->assigned_results_length);
							flow->assigned_results = NULL;
						}

						ifnet_t ifp = NULL;
						if ((inp->inp_flags & INP_BOUND_IF) && inp->inp_boundifp) {
							ifp = inp->inp_boundifp;
						} else {
							ifp = inp->inp_last_outifp;
						}

						if (ifp != NULL) {
							flow->interface_index = ifp->if_index;
						} else {
							flow->interface_index = IFSCOPE_NONE;
						}

						if (inp->inp_vflag & INP_IPV4) {
							flow->local_addr.sin.sin_family = AF_INET;
							flow->local_addr.sin.sin_len = sizeof(struct sockaddr_in);
							flow->local_addr.sin.sin_port = inp->inp_lport;
							memcpy(&flow->local_addr.sin.sin_addr, &inp->inp_laddr, sizeof(struct in_addr));

							flow->remote_addr.sin.sin_family = AF_INET;
							flow->remote_addr.sin.sin_len = sizeof(struct sockaddr_in);
							flow->remote_addr.sin.sin_port = inp->inp_fport;
							memcpy(&flow->remote_addr.sin.sin_addr, &inp->inp_faddr, sizeof(struct in_addr));
						} else if (inp->inp_vflag & INP_IPV6) {
							in6_ip6_to_sockaddr(&inp->in6p_laddr, inp->inp_lport, inp->inp_lifscope, &flow->local_addr.sin6, sizeof(flow->local_addr));
							in6_ip6_to_sockaddr(&inp->in6p_faddr, inp->inp_fport, inp->inp_fifscope, &flow->remote_addr.sin6, sizeof(flow->remote_addr));
						}

						flow->viable = necp_client_flow_is_viable(proc, client, flow);

						uuid_t empty_uuid;
						uuid_clear(empty_uuid);
						flow->assigned = TRUE;
						flow->assigned_results = necp_create_nexus_assign_message(empty_uuid, 0, NULL, 0,
						    (struct necp_client_endpoint *)&flow->local_addr,
						    (struct necp_client_endpoint *)&flow->remote_addr,
						    NULL, 0, NULL, &flow->assigned_results_length);
						flow_registration->flow_result_read = FALSE;
						client_updated = TRUE;
						break;
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (error == 0) {
		if (!found_client) {
			error = ENOENT;
		} else if (!client_updated) {
			error = EINVAL;
		}
	}

	return error;
}

bool
necp_socket_is_allowed_to_recv_on_interface(struct inpcb *inp, ifnet_t interface)
{
	if (interface == NULL ||
	    inp == NULL ||
	    !(inp->inp_flags2 & INP2_EXTERNAL_PORT) ||
	    uuid_is_null(inp->necp_client_uuid)) {
		// If there's no interface or client ID to check,
		// or if this is not a listener, pass.
		// Outbound connections will have already been
		// validated for policy.
		return TRUE;
	}

	// Only filter out listener sockets (no remote address specified)
	if ((inp->inp_vflag & INP_IPV4) &&
	    inp->inp_faddr.s_addr != INADDR_ANY) {
		return TRUE;
	}
	if ((inp->inp_vflag & INP_IPV6) &&
	    !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
		return TRUE;
	}

	bool allowed = TRUE;

	NECP_CLIENT_TREE_LOCK_SHARED();

	struct necp_client *client = necp_find_client_and_lock(inp->necp_client_uuid);
	if (client != NULL) {
		struct necp_client_parsed_parameters *parsed_parameters = NULL;

		parsed_parameters = kalloc_type(struct necp_client_parsed_parameters,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
		int error = necp_client_parse_parameters(client, client->parameters, (u_int32_t)client->parameters_length, parsed_parameters);
		if (error == 0) {
			if (!necp_ifnet_matches_parameters(interface, parsed_parameters, 0, NULL, true, false)) {
				allowed = FALSE;
			}
		}
		kfree_type(struct necp_client_parsed_parameters, parsed_parameters);

		NECP_CLIENT_UNLOCK(client);
	}

	NECP_CLIENT_TREE_UNLOCK();

	return allowed;
}

int
necp_update_flow_protoctl_event(uuid_t netagent_uuid, uuid_t client_id,
    uint32_t protoctl_event_code, uint32_t protoctl_event_val,
    uint32_t protoctl_event_tcp_seq_number)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();
	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);

		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;

				struct necp_client_flow *flow = NULL;
				LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
					// Verify that the client nexus agent matches
					if ((flow->nexus && uuid_compare(flow->u.nexus_agent, netagent_uuid) == 0) ||
					    flow->socket) {
						flow->has_protoctl_event = TRUE;
						flow->protoctl_event.protoctl_event_code = protoctl_event_code;
						flow->protoctl_event.protoctl_event_val = protoctl_event_val;
						flow->protoctl_event.protoctl_event_tcp_seq_num = protoctl_event_tcp_seq_number;
						flow_registration->flow_result_read = FALSE;
						client_updated = TRUE;
						break;
					}
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}

		if (client_updated) {
			necp_fd_notify(client_fd, true);
		}

		NECP_FD_UNLOCK(client_fd);
		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}
	NECP_FD_LIST_UNLOCK();

	if (!found_client) {
		error = ENOENT;
	} else if (!client_updated) {
		error = EINVAL;
	}
	return error;
}

static bool
necp_assign_client_result_locked(struct proc *proc,
    struct necp_fd_data *client_fd,
    struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    uuid_t netagent_uuid,
    u_int8_t *assigned_results,
    size_t assigned_results_length,
    bool notify_fd)
{
	bool client_updated = FALSE;

	NECP_FD_ASSERT_LOCKED(client_fd);
	NECP_CLIENT_ASSERT_LOCKED(client);

	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		// Verify that the client nexus agent matches
		if (flow->nexus &&
		    uuid_compare(flow->u.nexus_agent, netagent_uuid) == 0) {
			// Release prior results and route
			if (flow->assigned_results != NULL) {
				kfree_data(flow->assigned_results, flow->assigned_results_length);
				flow->assigned_results = NULL;
			}

			void *nexus_stats = NULL;
			if (assigned_results != NULL && assigned_results_length > 0) {
				int error = necp_client_parse_result(assigned_results, (u_int32_t)assigned_results_length,
				    &flow->local_addr, &flow->remote_addr, &nexus_stats);
				VERIFY(error == 0);
			}

			flow->viable = necp_client_flow_is_viable(proc, client, flow);

			flow->assigned = TRUE;
			flow->assigned_results = assigned_results;
			flow->assigned_results_length = assigned_results_length;
			flow_registration->flow_result_read = FALSE;
#if SKYWALK
			if (nexus_stats != NULL) {
				if (flow_registration->nexus_stats != NULL) {
					flow_stats_release(flow_registration->nexus_stats);
				}
				flow_registration->nexus_stats = nexus_stats;
			}
#endif /* SKYWALK */
			client_updated = TRUE;
			break;
		}
	}

	if (client_updated && notify_fd) {
		necp_fd_notify(client_fd, true);
	}

	// if not updated, client must free assigned_results
	return client_updated;
}

int
necp_assign_client_result(uuid_t netagent_uuid, uuid_t client_id,
    u_int8_t *assigned_results, size_t assigned_results_length)
{
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = FALSE;
	bool client_updated = FALSE;

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
			if (flow_registration != NULL) {
				// Found the right client and flow!
				found_client = TRUE;
				if (necp_assign_client_result_locked(proc, client_fd, client, flow_registration, netagent_uuid,
				    assigned_results, assigned_results_length, true)) {
					client_updated = TRUE;
				}
			}

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}

	NECP_FD_LIST_UNLOCK();

	// upon error, client must free assigned_results
	if (!found_client) {
		error = ENOENT;
	} else if (!client_updated) {
		error = EINVAL;
	}

	return error;
}

int
necp_assign_client_group_members(uuid_t netagent_uuid, uuid_t client_id,
    u_int8_t *assigned_group_members, size_t assigned_group_members_length)
{
#pragma unused(netagent_uuid)
	int error = 0;
	struct necp_fd_data *client_fd = NULL;
	bool found_client = false;
	bool client_updated = false;

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			found_client = true;
			// Release prior results
			if (client->assigned_group_members != NULL) {
				kfree_data(client->assigned_group_members, client->assigned_group_members_length);
				client->assigned_group_members = NULL;
			}

			// Save new results
			client->assigned_group_members = assigned_group_members;
			client->assigned_group_members_length = assigned_group_members_length;
			client->group_members_read = false;

			client_updated = true;
			necp_fd_notify(client_fd, true);

			NECP_CLIENT_UNLOCK(client);
		}
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;

		if (found_client) {
			break;
		}
	}

	NECP_FD_LIST_UNLOCK();

	// upon error, client must free assigned_results
	if (!found_client) {
		error = ENOENT;
	} else if (!client_updated) {
		error = EINVAL;
	}

	return error;
}

/// Client updating

static bool
necp_update_parsed_parameters(struct necp_client_parsed_parameters *parsed_parameters,
    struct necp_aggregate_result *result)
{
	if (parsed_parameters == NULL ||
	    result == NULL) {
		return false;
	}

	bool updated = false;
	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result->netagents[i])) {
			// Passed end of valid agents
			break;
		}

		if (!(result->netagent_use_flags[i] & NECP_AGENT_USE_FLAG_SCOPE)) {
			// Not a scoped agent, ignore
			continue;
		}

		// This is a scoped agent. Add it to the required agents.
		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
			// Already some required agents, add this at the end
			for (int j = 0; j < NECP_MAX_AGENT_PARAMETERS; j++) {
				if (uuid_compare(parsed_parameters->required_netagents[j], result->netagents[i]) == 0) {
					// Already required, break
					break;
				}
				if (uuid_is_null(parsed_parameters->required_netagents[j])) {
					// Add here
					memcpy(&parsed_parameters->required_netagents[j], result->netagents[i], sizeof(uuid_t));
					updated = true;
					break;
				}
			}
		} else {
			// No required agents yet, add this one
			parsed_parameters->valid_fields |= NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT;
			memcpy(&parsed_parameters->required_netagents[0], result->netagents[i], sizeof(uuid_t));
			updated = true;
		}

		// Remove requirements for agents of the same type
		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
			char remove_agent_domain[NETAGENT_DOMAINSIZE] = { 0 };
			char remove_agent_type[NETAGENT_TYPESIZE] = { 0 };
			if (netagent_get_agent_domain_and_type(result->netagents[i], remove_agent_domain, remove_agent_type)) {
				for (int j = 0; j < NECP_MAX_AGENT_PARAMETERS; j++) {
					if (strlen(parsed_parameters->required_netagent_types[j].netagent_domain) == 0 &&
					    strlen(parsed_parameters->required_netagent_types[j].netagent_type) == 0) {
						break;
					}

					if (strncmp(parsed_parameters->required_netagent_types[j].netagent_domain, remove_agent_domain, NETAGENT_DOMAINSIZE) == 0 &&
					    strncmp(parsed_parameters->required_netagent_types[j].netagent_type, remove_agent_type, NETAGENT_TYPESIZE) == 0) {
						updated = true;

						if (j == NECP_MAX_AGENT_PARAMETERS - 1) {
							// Last field, just clear and break
							memset(&parsed_parameters->required_netagent_types[NECP_MAX_AGENT_PARAMETERS - 1], 0, sizeof(struct necp_client_parameter_netagent_type));
							break;
						} else {
							// Move the parameters down, clear the last entry
							memmove(&parsed_parameters->required_netagent_types[j],
							    &parsed_parameters->required_netagent_types[j + 1],
							    sizeof(struct necp_client_parameter_netagent_type) * (NECP_MAX_AGENT_PARAMETERS - (j + 1)));
							memset(&parsed_parameters->required_netagent_types[NECP_MAX_AGENT_PARAMETERS - 1], 0, sizeof(struct necp_client_parameter_netagent_type));
							// Continue, don't increment but look at the new shifted item instead
							continue;
						}
					}

					// Increment j to look at the next agent type parameter
					j++;
				}
			}
		}
	}

	if (updated &&
	    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF) == 0) {
		// A required interface index was added after the fact. Clear it.
		parsed_parameters->required_interface_index = IFSCOPE_NONE;
	}


	return updated;
}

static inline bool
necp_agent_types_match(const char *agent_domain1, const char *agent_type1,
    const char *agent_domain2, const char *agent_type2)
{
	return (strlen(agent_domain1) == 0 ||
	       strncmp(agent_domain2, agent_domain1, NETAGENT_DOMAINSIZE) == 0) &&
	       (strlen(agent_type1) == 0 ||
	       strncmp(agent_type2, agent_type1, NETAGENT_TYPESIZE) == 0);
}

static inline bool
necp_calculate_client_result(proc_t proc,
    struct necp_client *client,
    struct necp_client_parsed_parameters *parsed_parameters,
    struct necp_aggregate_result *result,
    u_int32_t *flags,
    u_int32_t *reason,
    struct necp_client_endpoint *v4_gateway,
    struct necp_client_endpoint *v6_gateway,
    uuid_t *override_euuid)
{
	struct rtentry *route = NULL;

	// Check parameters to find best interface
	bool validate_agents = false;
	u_int matching_if_index = 0;
	if (necp_find_matching_interface_index(parsed_parameters, &matching_if_index, &validate_agents)) {
		if (matching_if_index != 0) {
			parsed_parameters->required_interface_index = matching_if_index;
		}
		// Interface found or not needed, match policy.
		memset(result, 0, sizeof(*result));
		int error = necp_application_find_policy_match_internal(proc, client->parameters,
		    (u_int32_t)client->parameters_length,
		    result, flags, reason, matching_if_index,
		    NULL, NULL,
		    v4_gateway, v6_gateway,
		    &route, false, true,
		    override_euuid);
		if (error != 0) {
			if (route != NULL) {
				rtfree(route);
			}
			return FALSE;
		}

		if (validate_agents) {
			bool requirement_failed = FALSE;
			if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
				for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
					if (uuid_is_null(parsed_parameters->required_netagents[i])) {
						break;
					}

					bool requirement_found = FALSE;
					for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
						if (uuid_is_null(result->netagents[j])) {
							break;
						}

						if (result->netagent_use_flags[j] & NECP_AGENT_USE_FLAG_REMOVE) {
							// A removed agent, ignore
							continue;
						}

						if (uuid_compare(parsed_parameters->required_netagents[i], result->netagents[j]) == 0) {
							requirement_found = TRUE;
							break;
						}
					}

					if (!requirement_found) {
						requirement_failed = TRUE;
						break;
					}
				}
			}

			if (!requirement_failed && parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
				for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
					if (strlen(parsed_parameters->required_netagent_types[i].netagent_domain) == 0 &&
					    strlen(parsed_parameters->required_netagent_types[i].netagent_type) == 0) {
						break;
					}

					bool requirement_found = FALSE;
					for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
						if (uuid_is_null(result->netagents[j])) {
							break;
						}

						if (result->netagent_use_flags[j] & NECP_AGENT_USE_FLAG_REMOVE) {
							// A removed agent, ignore
							continue;
						}

						char policy_agent_domain[NETAGENT_DOMAINSIZE] = { 0 };
						char policy_agent_type[NETAGENT_TYPESIZE] = { 0 };

						if (netagent_get_agent_domain_and_type(result->netagents[j], policy_agent_domain, policy_agent_type)) {
							if (necp_agent_types_match(parsed_parameters->required_netagent_types[i].netagent_domain,
							    parsed_parameters->required_netagent_types[i].netagent_type,
							    policy_agent_domain, policy_agent_type)) {
								requirement_found = TRUE;
								break;
							}
						}
					}

					if (!requirement_found) {
						requirement_failed = TRUE;
						break;
					}
				}
			}

			if (requirement_failed) {
				// Agent requirement failed. Clear out the whole result, make everything fail.
				memset(result, 0, sizeof(*result));
				if (route != NULL) {
					rtfree(route);
				}
				return TRUE;
			}
		}

		// Reset current route
		NECP_CLIENT_ROUTE_LOCK(client);
		if (client->current_route != NULL) {
			rtfree(client->current_route);
		}
		client->current_route = route;
		NECP_CLIENT_ROUTE_UNLOCK(client);
	} else {
		// Interface not found. Clear out the whole result, make everything fail.
		memset(result, 0, sizeof(*result));
	}

	return TRUE;
}

#define NECP_PARSED_PARAMETERS_REQUIRED_FIELDS (NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF |             \
	                                                                                        NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |          \
	                                                                                        NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |           \
	                                                                                        NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE)

static bool
necp_update_client_result(proc_t proc,
    struct necp_fd_data *client_fd,
    struct necp_client *client,
    struct _necp_flow_defunct_list *defunct_list)
{
	struct necp_client_result_netagent netagent;
	struct necp_aggregate_result result;
	struct necp_client_parsed_parameters *parsed_parameters = NULL;
	u_int32_t flags = 0;
	u_int32_t reason = 0;

	NECP_CLIENT_ASSERT_LOCKED(client);

	parsed_parameters = kalloc_type(struct necp_client_parsed_parameters,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	// Nexus flows will be brought back if they are still valid
	necp_client_mark_all_nonsocket_flows_as_invalid(client);

	int error = necp_client_parse_parameters(client, client->parameters, (u_int32_t)client->parameters_length, parsed_parameters);
	if (error != 0) {
		kfree_type(struct necp_client_parsed_parameters, parsed_parameters);
		return FALSE;
	}

	// Update saved IP protocol
	client->ip_protocol = parsed_parameters->ip_protocol;

	// Calculate the policy result
	struct necp_client_endpoint v4_gateway = {};
	struct necp_client_endpoint v6_gateway = {};
	uuid_t override_euuid;
	uuid_clear(override_euuid);
	if (!necp_calculate_client_result(proc, client, parsed_parameters, &result, &flags, &reason, &v4_gateway, &v6_gateway, &override_euuid)) {
		kfree_type(struct necp_client_parsed_parameters, parsed_parameters);
		return FALSE;
	}

	if (necp_update_parsed_parameters(parsed_parameters, &result)) {
		// Changed the parameters based on result, try again (only once)
		if (!necp_calculate_client_result(proc, client, parsed_parameters, &result, &flags, &reason, &v4_gateway, &v6_gateway, &override_euuid)) {
			kfree_type(struct necp_client_parsed_parameters, parsed_parameters);
			return FALSE;
		}
	}

	if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) &&
	    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF) == 0) {
		// Listener should not apply required interface index if
		parsed_parameters->required_interface_index = IFSCOPE_NONE;
	}

	// Save the last policy id on the client
	client->policy_id = result.policy_id;
	uuid_copy(client->override_euuid, override_euuid);

	if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_MULTIPATH) ||
	    (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_BROWSE) ||
	    ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) &&
	    result.routing_result != NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED)) {
		client->allow_multiple_flows = TRUE;
	} else {
		client->allow_multiple_flows = FALSE;
	}

	// If the original request was scoped, and the policy result matches, make sure the result is scoped
	if ((result.routing_result == NECP_KERNEL_POLICY_RESULT_NONE ||
	    result.routing_result == NECP_KERNEL_POLICY_RESULT_PASS) &&
	    result.routed_interface_index != IFSCOPE_NONE &&
	    parsed_parameters->required_interface_index == result.routed_interface_index) {
		result.routing_result = NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED;
		result.routing_result_parameter.scoped_interface_index = result.routed_interface_index;
	}

	if (defunct_list != NULL &&
	    result.routing_result == NECP_KERNEL_POLICY_RESULT_DROP) {
		// If we are forced to drop the client, defunct it if it has flows
		necp_defunct_client_for_policy(client, defunct_list);
	}

	// Recalculate flags
	if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) {
		// Listeners are valid as long as they aren't dropped
		if (result.routing_result != NECP_KERNEL_POLICY_RESULT_DROP) {
			flags |= NECP_CLIENT_RESULT_FLAG_SATISFIED;
		}
	} else if (result.routed_interface_index != 0) {
		// Clients without flows determine viability based on having some routable interface
		flags |= NECP_CLIENT_RESULT_FLAG_SATISFIED;
	}

	bool updated = FALSE;
	u_int8_t *cursor = client->result;
	cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_FLAGS, sizeof(flags), &flags, &updated, client->result, sizeof(client->result));
	if (reason != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_REASON, sizeof(reason), &reason, &updated, client->result, sizeof(client->result));
	}
	cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_CLIENT_ID, sizeof(uuid_t), client->client_id, &updated,
	    client->result, sizeof(client->result));
	cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_POLICY_RESULT, sizeof(result.routing_result), &result.routing_result, &updated,
	    client->result, sizeof(client->result));
	if (result.routing_result_parameter.tunnel_interface_index != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_POLICY_RESULT_PARAMETER,
		    sizeof(result.routing_result_parameter), &result.routing_result_parameter, &updated,
		    client->result, sizeof(client->result));
	}
	if (result.filter_control_unit != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_FILTER_CONTROL_UNIT,
		    sizeof(result.filter_control_unit), &result.filter_control_unit, &updated,
		    client->result, sizeof(client->result));
	}
	if (result.flow_divert_aggregate_unit != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_FLOW_DIVERT_AGGREGATE_UNIT,
		    sizeof(result.flow_divert_aggregate_unit), &result.flow_divert_aggregate_unit, &updated,
		    client->result, sizeof(client->result));
	}
	if (result.routed_interface_index != 0) {
		u_int routed_interface_index = result.routed_interface_index;
		if (result.routing_result == NECP_KERNEL_POLICY_RESULT_IP_TUNNEL &&
		    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_REQUIRED_FIELDS) &&
		    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
		    parsed_parameters->required_interface_index != result.routed_interface_index) {
			routed_interface_index = parsed_parameters->required_interface_index;
		}

		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_INDEX,
		    sizeof(routed_interface_index), &routed_interface_index, &updated,
		    client->result, sizeof(client->result));
	}
	if (client_fd && client_fd->flags & NECP_OPEN_FLAG_BACKGROUND) {
		u_int32_t effective_traffic_class = SO_TC_BK_SYS;
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_EFFECTIVE_TRAFFIC_CLASS,
		    sizeof(effective_traffic_class), &effective_traffic_class, &updated,
		    client->result, sizeof(client->result));
	}

	if (client_fd->background) {
		bool has_assigned_flow = FALSE;
		struct necp_client_flow_registration *flow_registration = NULL;
		struct necp_client_flow *search_flow = NULL;
		RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
			LIST_FOREACH(search_flow, &flow_registration->flow_list, flow_chain) {
				if (search_flow->assigned) {
					has_assigned_flow = TRUE;
					break;
				}
			}
		}

		if (has_assigned_flow) {
			u_int32_t background = client_fd->background;
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_TRAFFIC_MGMT_BG,
			    sizeof(background), &background, &updated,
			    client->result, sizeof(client->result));
		}
	}

	bool write_v4_gateway = !necp_client_endpoint_is_unspecified(&v4_gateway);
	bool write_v6_gateway = !necp_client_endpoint_is_unspecified(&v6_gateway);

	NECP_CLIENT_ROUTE_LOCK(client);
	if (client->current_route != NULL) {
		const u_int32_t route_mtu = get_maxmtu(client->current_route);
		if (route_mtu != 0) {
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_EFFECTIVE_MTU,
			    sizeof(route_mtu), &route_mtu, &updated,
			    client->result, sizeof(client->result));
		}
		bool has_remote_addr = parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REMOTE_ADDR;
		if (has_remote_addr && client->current_route->rt_gateway != NULL) {
			if (client->current_route->rt_gateway->sa_family == AF_INET) {
				write_v6_gateway = false;
			} else if (client->current_route->rt_gateway->sa_family == AF_INET6) {
				write_v4_gateway = false;
			}
		}
	}
	NECP_CLIENT_ROUTE_UNLOCK(client);

	if (write_v4_gateway) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_GATEWAY,
		    sizeof(struct necp_client_endpoint), &v4_gateway, &updated,
		    client->result, sizeof(client->result));
	}

	if (write_v6_gateway) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_GATEWAY,
		    sizeof(struct necp_client_endpoint), &v6_gateway, &updated,
		    client->result, sizeof(client->result));
	}

	for (int i = 0; i < NAT64_MAX_NUM_PREFIXES; i++) {
		if (result.nat64_prefixes[i].prefix_len != 0) {
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NAT64,
			    sizeof(result.nat64_prefixes), result.nat64_prefixes, &updated,
			    client->result, sizeof(client->result));
			break;
		}
	}

	if (result.mss_recommended != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_RECOMMENDED_MSS,
		    sizeof(result.mss_recommended), &result.mss_recommended, &updated,
		    client->result, sizeof(client->result));
	}

	for (int i = 0; i < NECP_MAX_NETAGENTS; i++) {
		if (uuid_is_null(result.netagents[i])) {
			break;
		}
		if (result.netagent_use_flags[i] & NECP_AGENT_USE_FLAG_REMOVE) {
			// A removed agent, ignore
			continue;
		}
		uuid_copy(netagent.netagent_uuid, result.netagents[i]);
		netagent.generation = netagent_get_generation(netagent.netagent_uuid);
		if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, TRUE, 0, 0)) {
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
			    client->result, sizeof(client->result));
		}
	}

	ifnet_head_lock_shared();
	ifnet_t direct_interface = NULL;
	ifnet_t delegate_interface = NULL;
	ifnet_t original_scoped_interface = NULL;

	if (result.routed_interface_index != IFSCOPE_NONE && result.routed_interface_index <= (u_int32_t)if_index) {
		direct_interface = ifindex2ifnet[result.routed_interface_index];
	} else if (parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    parsed_parameters->required_interface_index <= (u_int32_t)if_index) {
		// If the request was scoped, but the route didn't match, still grab the agents
		direct_interface = ifindex2ifnet[parsed_parameters->required_interface_index];
	} else if (result.routed_interface_index == IFSCOPE_NONE &&
	    result.routing_result == NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED &&
	    result.routing_result_parameter.scoped_interface_index != IFSCOPE_NONE) {
		direct_interface = ifindex2ifnet[result.routing_result_parameter.scoped_interface_index];
	}
	if (direct_interface != NULL) {
		delegate_interface = direct_interface->if_delegated.ifp;
	}
	if (result.routing_result == NECP_KERNEL_POLICY_RESULT_IP_TUNNEL &&
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_REQUIRED_FIELDS) &&
	    parsed_parameters->required_interface_index != IFSCOPE_NONE &&
	    parsed_parameters->required_interface_index != result.routing_result_parameter.tunnel_interface_index &&
	    parsed_parameters->required_interface_index <= (u_int32_t)if_index) {
		original_scoped_interface = ifindex2ifnet[parsed_parameters->required_interface_index];
	}
	// Add interfaces
	if (original_scoped_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = original_scoped_interface->if_index;
		interface_struct.generation = ifnet_get_generation(original_scoped_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated,
		    client->result, sizeof(client->result));
	}
	if (direct_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = direct_interface->if_index;
		interface_struct.generation = ifnet_get_generation(direct_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated,
		    client->result, sizeof(client->result));

		// Set the delta time since interface up/down
		struct timeval updown_delta = {};
		if (ifnet_updown_delta(direct_interface, &updown_delta) == 0) {
			u_int32_t delta = updown_delta.tv_sec;
			bool ignore_updated = FALSE;
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_TIME_DELTA,
			    sizeof(delta), &delta, &ignore_updated,
			    client->result, sizeof(client->result));
		}
	}
	if (delegate_interface != NULL) {
		struct necp_client_result_interface interface_struct;
		interface_struct.index = delegate_interface->if_index;
		interface_struct.generation = ifnet_get_generation(delegate_interface);
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE, sizeof(interface_struct), &interface_struct, &updated,
		    client->result, sizeof(client->result));
	}

	// Update multipath/listener interface flows
	if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_MULTIPATH) {
		// Add the interface option for the routed interface first
		if (direct_interface != NULL) {
			// Add nexus agent
			necp_client_add_agent_interface_options(client, parsed_parameters, direct_interface);

			// Add interface option in case it is not a nexus
			necp_client_add_interface_option_if_needed(client, direct_interface->if_index,
			    ifnet_get_generation(direct_interface), NULL, false);
		}
		// Get other multipath interface options from ordered list
		struct ifnet *multi_interface = NULL;
		TAILQ_FOREACH(multi_interface, &ifnet_ordered_head, if_ordered_link) {
			if (multi_interface != direct_interface &&
			    necp_ifnet_matches_parameters(multi_interface, parsed_parameters, 0, NULL, true, false)) {
				// Add nexus agents for multipath
				necp_client_add_agent_interface_options(client, parsed_parameters, multi_interface);

				// Add multipath interface flows for kernel MPTCP
				necp_client_add_interface_option_if_needed(client, multi_interface->if_index,
				    ifnet_get_generation(multi_interface), NULL, false);
			}
		}
	} else if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) {
		if (result.routing_result == NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED) {
			if (direct_interface != NULL) {
				// If scoped, only listen on that interface
				// Add nexus agents for listeners
				necp_client_add_agent_interface_options(client, parsed_parameters, direct_interface);

				// Add interface option in case it is not a nexus
				necp_client_add_interface_option_if_needed(client, direct_interface->if_index,
				    ifnet_get_generation(direct_interface), NULL, false);
			}
		} else {
			// Get listener interface options from global list
			struct ifnet *listen_interface = NULL;
			TAILQ_FOREACH(listen_interface, &ifnet_head, if_link) {
				if ((listen_interface->if_flags & (IFF_UP | IFF_RUNNING)) &&
				    necp_ifnet_matches_parameters(listen_interface, parsed_parameters, 0, NULL, true, false)) {
					// Add nexus agents for listeners
					necp_client_add_agent_interface_options(client, parsed_parameters, listen_interface);
				}
			}
		}
	} else if (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_BROWSE) {
		if (result.routing_result == NECP_KERNEL_POLICY_RESULT_SOCKET_SCOPED) {
			if (direct_interface != NULL) {
				// Add browse option if it has an agent
				necp_client_add_browse_interface_options(client, parsed_parameters, direct_interface);
			}
		} else {
			// Get browse interface options from global list
			struct ifnet *browse_interface = NULL;
			TAILQ_FOREACH(browse_interface, &ifnet_head, if_link) {
				if (necp_ifnet_matches_parameters(browse_interface, parsed_parameters, 0, NULL, true, false)) {
					necp_client_add_browse_interface_options(client, parsed_parameters, browse_interface);
				}
			}
		}
	}

	struct necp_client_result_estimated_throughput throughput = {
		.up = 0,
		.down = 0,
	};

	// Add agents
	if (original_scoped_interface != NULL) {
		ifnet_lock_shared(original_scoped_interface);
		if (original_scoped_interface->if_agentids != NULL) {
			for (u_int32_t i = 0; i < original_scoped_interface->if_agentcount; i++) {
				if (uuid_is_null(original_scoped_interface->if_agentids[i])) {
					continue;
				}
				bool skip_agent = false;
				for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
					if (uuid_is_null(result.netagents[j])) {
						break;
					}
					if ((result.netagent_use_flags[j] & NECP_AGENT_USE_FLAG_REMOVE) &&
					    uuid_compare(original_scoped_interface->if_agentids[i], result.netagents[j]) == 0) {
						skip_agent = true;
						break;
					}
				}
				if (skip_agent) {
					continue;
				}
				uuid_copy(netagent.netagent_uuid, original_scoped_interface->if_agentids[i]);
				netagent.generation = netagent_get_generation(netagent.netagent_uuid);
				if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, FALSE,
				    original_scoped_interface->if_index, ifnet_get_generation(original_scoped_interface))) {
					cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
					    client->result, sizeof(client->result));
				}
			}
		}
		ifnet_lock_done(original_scoped_interface);
	}
	if (direct_interface != NULL) {
		ifnet_lock_shared(direct_interface);
		throughput.up = direct_interface->if_estimated_up_bucket;
		throughput.down = direct_interface->if_estimated_down_bucket;
		if (direct_interface->if_agentids != NULL) {
			for (u_int32_t i = 0; i < direct_interface->if_agentcount; i++) {
				if (uuid_is_null(direct_interface->if_agentids[i])) {
					continue;
				}
				bool skip_agent = false;
				for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
					if (uuid_is_null(result.netagents[j])) {
						break;
					}
					if ((result.netagent_use_flags[j] & NECP_AGENT_USE_FLAG_REMOVE) &&
					    uuid_compare(direct_interface->if_agentids[i], result.netagents[j]) == 0) {
						skip_agent = true;
						break;
					}
				}
				if (skip_agent) {
					continue;
				}
				uuid_copy(netagent.netagent_uuid, direct_interface->if_agentids[i]);
				netagent.generation = netagent_get_generation(netagent.netagent_uuid);
				if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, TRUE,
				    direct_interface->if_index, ifnet_get_generation(direct_interface))) {
					cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
					    client->result, sizeof(client->result));
				}
			}
		}
		ifnet_lock_done(direct_interface);
	}
	if (delegate_interface != NULL) {
		ifnet_lock_shared(delegate_interface);
		if (throughput.up == 0 && throughput.down == 0) {
			throughput.up = delegate_interface->if_estimated_up_bucket;
			throughput.down = delegate_interface->if_estimated_down_bucket;
		}
		if (delegate_interface->if_agentids != NULL) {
			for (u_int32_t i = 0; i < delegate_interface->if_agentcount; i++) {
				if (uuid_is_null(delegate_interface->if_agentids[i])) {
					continue;
				}
				bool skip_agent = false;
				for (int j = 0; j < NECP_MAX_NETAGENTS; j++) {
					if (uuid_is_null(result.netagents[j])) {
						break;
					}
					if ((result.netagent_use_flags[j] & NECP_AGENT_USE_FLAG_REMOVE) &&
					    uuid_compare(delegate_interface->if_agentids[i], result.netagents[j]) == 0) {
						skip_agent = true;
						break;
					}
				}
				if (skip_agent) {
					continue;
				}
				uuid_copy(netagent.netagent_uuid, delegate_interface->if_agentids[i]);
				netagent.generation = netagent_get_generation(netagent.netagent_uuid);
				if (necp_netagent_applies_to_client(client, parsed_parameters, &netagent.netagent_uuid, FALSE,
				    delegate_interface->if_index, ifnet_get_generation(delegate_interface))) {
					cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_NETAGENT, sizeof(netagent), &netagent, &updated,
					    client->result, sizeof(client->result));
				}
			}
		}
		ifnet_lock_done(delegate_interface);
	}
	ifnet_head_done();

	if (throughput.up != 0 || throughput.down != 0) {
		cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_ESTIMATED_THROUGHPUT,
		    sizeof(throughput), &throughput, &updated, client->result, sizeof(client->result));
	}

	// Add interface options
	for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
		if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
			struct necp_client_interface_option *option = &client->interface_options[option_i];
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_OPTION, sizeof(*option), option, &updated,
			    client->result, sizeof(client->result));
		} else {
			struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
			cursor = necp_buffer_write_tlv_if_different(cursor, NECP_CLIENT_RESULT_INTERFACE_OPTION, sizeof(*option), option, &updated,
			    client->result, sizeof(client->result));
		}
	}

	size_t new_result_length = (cursor - client->result);
	if (new_result_length != client->result_length) {
		client->result_length = new_result_length;
		updated = TRUE;
	}

	// Update flow viability/flags
	if (necp_client_update_flows(proc, client, defunct_list)) {
		updated = TRUE;
	}

	if (updated) {
		client->result_read = FALSE;
		necp_client_update_observer_update(client);
	}

	kfree_type(struct necp_client_parsed_parameters, parsed_parameters);
	return updated;
}

static bool
necp_defunct_client_fd_locked_inner(struct necp_fd_data *client_fd, struct _necp_flow_defunct_list *defunct_list, bool destroy_stats)
{
	bool updated_result = FALSE;
	struct necp_client *client = NULL;

	NECP_FD_ASSERT_LOCKED(client_fd);

	RB_FOREACH(client, _necp_client_tree, &client_fd->clients) {
		struct necp_client_flow_registration *flow_registration = NULL;

		NECP_CLIENT_LOCK(client);

		// Prepare close events to be sent to the nexus to effectively remove the flows
		struct necp_client_flow *search_flow = NULL;
		RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
			LIST_FOREACH(search_flow, &flow_registration->flow_list, flow_chain) {
				if (search_flow->nexus &&
				    !uuid_is_null(search_flow->u.nexus_agent)) {
					// Sleeping alloc won't fail; copy only what's necessary
					struct necp_flow_defunct *flow_defunct = kalloc_type(struct necp_flow_defunct, Z_WAITOK | Z_ZERO);
					uuid_copy(flow_defunct->nexus_agent, search_flow->u.nexus_agent);
					uuid_copy(flow_defunct->flow_id, ((flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
					    client->client_id :
					    flow_registration->registration_id));
					flow_defunct->proc_pid = client->proc_pid;
					flow_defunct->agent_handle = client->agent_handle;
					flow_defunct->flags = flow_registration->flags;
#if SKYWALK
					if (flow_registration->kstats_kaddr != NULL) {
						struct necp_all_stats *ustats_kaddr = ((struct necp_all_kstats *)flow_registration->kstats_kaddr)->necp_stats_ustats;
						struct necp_quic_stats *quicstats = (struct necp_quic_stats *)ustats_kaddr;
						if (quicstats != NULL &&
						    quicstats->necp_quic_udp_stats.necp_udp_hdr.necp_stats_type == NECP_CLIENT_STATISTICS_TYPE_QUIC) {
							memcpy(flow_defunct->close_parameters.u.close_token, quicstats->necp_quic_extra.ssr_token, sizeof(flow_defunct->close_parameters.u.close_token));
							flow_defunct->has_close_parameters = true;
						}
					}
#endif /* SKYWALK */
					// Add to the list provided by caller
					LIST_INSERT_HEAD(defunct_list, flow_defunct, chain);

					flow_registration->defunct = true;
					flow_registration->flow_result_read = false;
					updated_result = true;
				}
			}
		}
		if (destroy_stats) {
#if SKYWALK
			// Free any remaining stats objects back to the arena where they came from;
			// do this independent of the above defunct check, as the client may have
			// been marked as defunct separately via necp_defunct_client_for_policy().
			RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
				necp_destroy_flow_stats(client_fd, flow_registration, NULL, FALSE);
			}
#endif /* SKYWALK */
		}
		NECP_CLIENT_UNLOCK(client);
	}

	return updated_result;
}

static inline void
necp_defunct_client_fd_locked(struct necp_fd_data *client_fd, struct _necp_flow_defunct_list *defunct_list, struct proc *proc)
{
#pragma unused(proc)
	bool updated_result = FALSE;

	NECP_FD_ASSERT_LOCKED(client_fd);
#if SKYWALK
	// redirect regions of currently-active stats arena to zero-filled pages
	struct necp_arena_info *nai = necp_fd_mredirect_stats_arena(client_fd, proc);
#endif /* SKYWALK */

	updated_result = necp_defunct_client_fd_locked_inner(client_fd, defunct_list, true);

#if SKYWALK
	// and tear down the currently-active arena's regions now that the redirection and freeing are done
	if (nai != NULL) {
		ASSERT((nai->nai_flags & (NAIF_REDIRECT | NAIF_DEFUNCT)) == NAIF_REDIRECT);
		ASSERT(nai->nai_arena != NULL);
		ASSERT(nai->nai_mmap.ami_mapref != NULL);

		int err = skmem_arena_defunct(nai->nai_arena);
		VERIFY(err == 0);

		nai->nai_flags |= NAIF_DEFUNCT;
	}
#endif /* SKYWALK */

	if (updated_result) {
		necp_fd_notify(client_fd, true);
	}
}

static inline void
necp_update_client_fd_locked(struct necp_fd_data *client_fd,
    proc_t proc,
    struct _necp_flow_defunct_list *defunct_list)
{
	struct necp_client *client = NULL;
	bool updated_result = FALSE;
	NECP_FD_ASSERT_LOCKED(client_fd);
	RB_FOREACH(client, _necp_client_tree, &client_fd->clients) {
		NECP_CLIENT_LOCK(client);
		if (necp_update_client_result(proc, client_fd, client, defunct_list)) {
			updated_result = TRUE;
		}
		NECP_CLIENT_UNLOCK(client);
	}
	if (updated_result) {
		necp_fd_notify(client_fd, true);
	}
}

#if SKYWALK
static void
necp_close_empty_arenas_callout(__unused thread_call_param_t dummy,
    __unused thread_call_param_t arg)
{
	struct necp_fd_data *client_fd = NULL;

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(client_fd);
		necp_stats_arenas_destroy(client_fd, FALSE);
		NECP_FD_UNLOCK(client_fd);
	}

	NECP_FD_LIST_UNLOCK();
}
#endif /* SKYWALK */

static void
necp_update_all_clients_callout(__unused thread_call_param_t dummy,
    __unused thread_call_param_t arg)
{
	struct necp_fd_data *client_fd = NULL;

	struct _necp_flow_defunct_list defunct_list;
	LIST_INIT(&defunct_list);

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		proc_t proc = proc_find(client_fd->proc_pid);
		if (proc == PROC_NULL) {
			continue;
		}

		// Update all clients on one fd
		NECP_FD_LOCK(client_fd);
		necp_update_client_fd_locked(client_fd, proc, &defunct_list);
		NECP_FD_UNLOCK(client_fd);

		proc_rele(proc);
		proc = PROC_NULL;
	}

	NECP_FD_LIST_UNLOCK();

	// Handle the case in which some clients became newly defunct
	necp_process_defunct_list(&defunct_list);
}

void
necp_update_all_clients(void)
{
	necp_update_all_clients_immediately_if_needed(false);
}

void
necp_update_all_clients_immediately_if_needed(bool should_update_immediately)
{
	if (necp_client_update_tcall == NULL) {
		// Don't try to update clients if the module is not initialized
		return;
	}

	uint64_t deadline = 0;
	uint64_t leeway = 0;

	uint32_t timeout_to_use = necp_timeout_microseconds;
	uint32_t leeway_to_use = necp_timeout_leeway_microseconds;
	if (should_update_immediately) {
		timeout_to_use = 1000 * 10; // 10ms
		leeway_to_use = 1000 * 10; // 10ms;
	}

	clock_interval_to_deadline(timeout_to_use, NSEC_PER_USEC, &deadline);
	clock_interval_to_absolutetime_interval(leeway_to_use, NSEC_PER_USEC, &leeway);

	thread_call_enter_delayed_with_leeway(necp_client_update_tcall, NULL,
	    deadline, leeway, THREAD_CALL_DELAY_LEEWAY);
}

bool
necp_set_client_as_background(proc_t proc,
    struct fileproc *fp,
    bool background)
{
	if (proc == PROC_NULL) {
		NECPLOG0(LOG_ERR, "NULL proc");
		return FALSE;
	}

	if (fp == NULL) {
		NECPLOG0(LOG_ERR, "NULL fp");
		return FALSE;
	}

	struct necp_fd_data *client_fd = (struct necp_fd_data *)fp_get_data(fp);
	if (client_fd == NULL) {
		NECPLOG0(LOG_ERR, "Could not find client structure for backgrounded client");
		return FALSE;
	}

	if (client_fd->necp_fd_type != necp_fd_type_client) {
		// Not a client fd, ignore
		NECPLOG0(LOG_ERR, "Not a client fd, ignore");
		return FALSE;
	}

	client_fd->background = background;

	return TRUE;
}

void
necp_fd_memstatus(proc_t proc, uint32_t status,
    struct necp_fd_data *client_fd)
{
#pragma unused(proc, status, client_fd)
	ASSERT(proc != PROC_NULL);
	ASSERT(client_fd != NULL);

	// Nothing to reap for the process or client for now,
	// but this is where we would trigger that in future.
}

void
necp_fd_defunct(proc_t proc, struct necp_fd_data *client_fd)
{
	struct _necp_flow_defunct_list defunct_list;

	ASSERT(proc != PROC_NULL);
	ASSERT(client_fd != NULL);

	if (client_fd->necp_fd_type != necp_fd_type_client) {
		// Not a client fd, ignore
		return;
	}

	// Our local temporary list
	LIST_INIT(&defunct_list);

	// Need to hold lock so ntstats defunct the same set of clients
	NECP_FD_LOCK(client_fd);
#if SKYWALK
	// Shut down statistics
	nstats_userland_stats_defunct_for_process(proc_getpid(proc));
#endif /* SKYWALK */
	necp_defunct_client_fd_locked(client_fd, &defunct_list, proc);
	NECP_FD_UNLOCK(client_fd);

	necp_process_defunct_list(&defunct_list);
}

static void
necp_client_remove_agent_from_result(struct necp_client *client, uuid_t netagent_uuid)
{
	size_t offset = 0;

	u_int8_t *result_buffer = client->result;
	while ((offset + sizeof(struct necp_tlv_header)) <= client->result_length) {
		u_int8_t type = necp_buffer_get_tlv_type(result_buffer, offset);
		u_int32_t length = necp_buffer_get_tlv_length(result_buffer, offset);

		size_t tlv_total_length = (sizeof(struct necp_tlv_header) + length);
		if (type == NECP_CLIENT_RESULT_NETAGENT &&
		    length == sizeof(struct necp_client_result_netagent) &&
		    (offset + tlv_total_length) <= client->result_length) {
			struct necp_client_result_netagent *value = ((struct necp_client_result_netagent *)(void *)
			    necp_buffer_get_tlv_value(result_buffer, offset, NULL));
			if (uuid_compare(value->netagent_uuid, netagent_uuid) == 0) {
				// Found a netagent to remove
				// Shift bytes down to remove the tlv, and adjust total length
				// Don't adjust the current offset
				memmove(result_buffer + offset,
				    result_buffer + offset + tlv_total_length,
				    client->result_length - (offset + tlv_total_length));
				client->result_length -= tlv_total_length;
				memset(result_buffer + client->result_length, 0, sizeof(client->result) - client->result_length);
				continue;
			}
		}

		offset += tlv_total_length;
	}
}

void
necp_force_update_client(uuid_t client_id, uuid_t remove_netagent_uuid, u_int32_t agent_generation)
{
	struct necp_fd_data *client_fd = NULL;

	NECP_FD_LIST_LOCK_SHARED();

	LIST_FOREACH(client_fd, &necp_fd_list, chain) {
		bool updated_result = FALSE;
		NECP_FD_LOCK(client_fd);
		struct necp_client *client = necp_client_fd_find_client_and_lock(client_fd, client_id);
		if (client != NULL) {
			client->failed_trigger_agent.generation = agent_generation;
			uuid_copy(client->failed_trigger_agent.netagent_uuid, remove_netagent_uuid);
			if (!uuid_is_null(remove_netagent_uuid)) {
				necp_client_remove_agent_from_result(client, remove_netagent_uuid);
			}
			client->result_read = FALSE;
			// Found the client, break
			updated_result = TRUE;
			NECP_CLIENT_UNLOCK(client);
		}
		if (updated_result) {
			necp_fd_notify(client_fd, true);
		}
		NECP_FD_UNLOCK(client_fd);
		if (updated_result) {
			// Found the client, break
			break;
		}
	}

	NECP_FD_LIST_UNLOCK();
}

#if SKYWALK
void
necp_client_early_close(uuid_t client_id)
{
	NECP_CLIENT_TREE_LOCK_SHARED();

	struct necp_client *client = necp_find_client_and_lock(client_id);
	if (client != NULL) {
		struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
		if (flow_registration != NULL) {
			// Found the right client and flow, mark the stats as over
			if (flow_registration->stats_handler_context != NULL) {
				ntstat_userland_stats_event(flow_registration->stats_handler_context,
				    NECP_CLIENT_STATISTICS_EVENT_TIME_WAIT);
			}
		}
		NECP_CLIENT_UNLOCK(client);
	}

	NECP_CLIENT_TREE_UNLOCK();
}
#endif /* SKYWALK */

/// Interface matching

#define NECP_PARSED_PARAMETERS_INTERESTING_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |                              \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF |                   \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |                 \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE |               \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |                  \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT |                \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |                 \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT |                   \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE |             \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE |   \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE |    \
	                                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE)

#define NECP_PARSED_PARAMETERS_SCOPED_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |                 \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE |                \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT |         \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |                \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE |    \
	                                                                                  NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE)

#define NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS (NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR |           \
	                                                                                                NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE)

#define NECP_PARSED_PARAMETERS_PREFERRED_FIELDS (NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT |                 \
	                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT |                   \
	                                                                                         NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE |    \
	                                                                                         NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE)

static bool
necp_ifnet_matches_type(struct ifnet *ifp, u_int8_t interface_type, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;
	while (check_ifp) {
		if (if_functional_type(check_ifp, TRUE) == interface_type) {
			return TRUE;
		}
		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_name(struct ifnet *ifp, const char *interface_name, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;
	while (check_ifp) {
		if (strncmp(check_ifp->if_xname, interface_name, IFXNAMSIZ) == 0) {
			return TRUE;
		}
		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_agent(struct ifnet *ifp, uuid_t *agent_uuid, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;

	while (check_ifp != NULL) {
		ifnet_lock_shared(check_ifp);
		if (check_ifp->if_agentids != NULL) {
			for (u_int32_t index = 0; index < check_ifp->if_agentcount; index++) {
				if (uuid_compare(check_ifp->if_agentids[index], *agent_uuid) == 0) {
					ifnet_lock_done(check_ifp);
					return TRUE;
				}
			}
		}
		ifnet_lock_done(check_ifp);

		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_agent_type(struct ifnet *ifp, const char *agent_domain, const char *agent_type, bool check_delegates)
{
	struct ifnet *check_ifp = ifp;

	while (check_ifp != NULL) {
		ifnet_lock_shared(check_ifp);
		if (check_ifp->if_agentids != NULL) {
			for (u_int32_t index = 0; index < check_ifp->if_agentcount; index++) {
				if (uuid_is_null(check_ifp->if_agentids[index])) {
					continue;
				}

				char if_agent_domain[NETAGENT_DOMAINSIZE] = { 0 };
				char if_agent_type[NETAGENT_TYPESIZE] = { 0 };

				if (netagent_get_agent_domain_and_type(check_ifp->if_agentids[index], if_agent_domain, if_agent_type)) {
					if (necp_agent_types_match(agent_domain, agent_type, if_agent_domain, if_agent_type)) {
						ifnet_lock_done(check_ifp);
						return TRUE;
					}
				}
			}
		}
		ifnet_lock_done(check_ifp);

		if (!check_delegates) {
			break;
		}
		check_ifp = check_ifp->if_delegated.ifp;
	}
	return FALSE;
}

static bool
necp_ifnet_matches_local_address(struct ifnet *ifp, struct sockaddr *sa)
{
	struct ifaddr *ifa = NULL;
	bool matched_local_address = FALSE;

	// Transform sa into the ifaddr form
	// IPv6 Scope IDs are always embedded in the ifaddr list
	struct sockaddr_storage address;
	u_int ifscope = IFSCOPE_NONE;
	(void)sa_copy(sa, &address, &ifscope);
	SIN(&address)->sin_port = 0;
	if (address.ss_family == AF_INET6) {
		if (in6_embedded_scope ||
		    !IN6_IS_SCOPE_EMBED(&SIN6(&address)->sin6_addr)) {
			SIN6(&address)->sin6_scope_id = 0;
		}
	}

	ifa = ifa_ifwithaddr_scoped_locked((struct sockaddr *)&address, ifp->if_index);
	matched_local_address = (ifa != NULL);

	if (ifa) {
		ifaddr_release(ifa);
	}

	return matched_local_address;
}

static bool
necp_interface_type_is_primary_eligible(u_int8_t interface_type)
{
	switch (interface_type) {
	// These types can never be primary, so a client requesting these types is allowed
	// to match an interface that isn't currently eligible to be primary (has default
	// route, dns, etc)
	case IFRTYPE_FUNCTIONAL_WIFI_AWDL:
	case IFRTYPE_FUNCTIONAL_INTCOPROC:
		return false;
	default:
		break;
	}
	return true;
}

#define NECP_IFP_IS_ON_ORDERED_LIST(_ifp) ((_ifp)->if_ordered_link.tqe_next != NULL || (_ifp)->if_ordered_link.tqe_prev != NULL)

// Secondary interface flag indicates that the interface is being
// used for multipath or a listener as an extra path
static bool
necp_ifnet_matches_parameters(struct ifnet *ifp,
    struct necp_client_parsed_parameters *parsed_parameters,
    u_int32_t override_flags,
    u_int32_t *preferred_count,
    bool secondary_interface,
    bool require_scoped_field)
{
	bool matched_some_scoped_field = FALSE;

	if (preferred_count) {
		*preferred_count = 0;
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IF) {
		if (parsed_parameters->required_interface_index != ifp->if_index) {
			return FALSE;
		}
	}
#if SKYWALK
	else {
		if (ifnet_is_low_latency(ifp)) {
			return FALSE;
		}
	}
#endif /* SKYWALK */

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR) {
		if (!necp_ifnet_matches_local_address(ifp, &parsed_parameters->local_addr.sa)) {
			return FALSE;
		}
		if (require_scoped_field) {
			matched_some_scoped_field = TRUE;
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_FLAGS) {
		if (override_flags != 0) {
			if ((override_flags & NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_EXPENSIVE) &&
			    IFNET_IS_EXPENSIVE(ifp)) {
				return FALSE;
			}
			if ((override_flags & NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_CONSTRAINED) &&
			    IFNET_IS_CONSTRAINED(ifp)) {
				return FALSE;
			}
		} else {
			if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_EXPENSIVE) &&
			    IFNET_IS_EXPENSIVE(ifp)) {
				return FALSE;
			}
			if ((parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_CONSTRAINED) &&
			    IFNET_IS_CONSTRAINED(ifp)) {
				return FALSE;
			}
		}
	}

	if ((!secondary_interface || // Enforce interface type if this is the primary interface
	    !(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_FLAGS) ||      // or if there are no flags
	    !(parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_ONLY_PRIMARY_REQUIRES_TYPE)) &&      // or if the flags don't give an exception
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) &&
	    !necp_ifnet_matches_type(ifp, parsed_parameters->required_interface_type, FALSE)) {
		return FALSE;
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE) {
		if (require_scoped_field) {
			matched_some_scoped_field = TRUE;
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IFTYPE) {
		for (int i = 0; i < NECP_MAX_INTERFACE_PARAMETERS; i++) {
			if (parsed_parameters->prohibited_interface_types[i] == 0) {
				break;
			}

			if (necp_ifnet_matches_type(ifp, parsed_parameters->prohibited_interface_types[i], TRUE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_IF) {
		for (int i = 0; i < NECP_MAX_INTERFACE_PARAMETERS; i++) {
			if (strlen(parsed_parameters->prohibited_interfaces[i]) == 0) {
				break;
			}

			if (necp_ifnet_matches_name(ifp, parsed_parameters->prohibited_interfaces[i], TRUE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT) {
		for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
			if (uuid_is_null(parsed_parameters->required_netagents[i])) {
				break;
			}

			if (!necp_ifnet_matches_agent(ifp, &parsed_parameters->required_netagents[i], FALSE)) {
				return FALSE;
			}

			if (require_scoped_field) {
				matched_some_scoped_field = TRUE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT) {
		for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
			if (uuid_is_null(parsed_parameters->prohibited_netagents[i])) {
				break;
			}

			if (necp_ifnet_matches_agent(ifp, &parsed_parameters->prohibited_netagents[i], TRUE)) {
				return FALSE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_AGENT_TYPE) {
		for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
			if (strlen(parsed_parameters->required_netagent_types[i].netagent_domain) == 0 &&
			    strlen(parsed_parameters->required_netagent_types[i].netagent_type) == 0) {
				break;
			}

			if (!necp_ifnet_matches_agent_type(ifp, parsed_parameters->required_netagent_types[i].netagent_domain, parsed_parameters->required_netagent_types[i].netagent_type, FALSE)) {
				return FALSE;
			}

			if (require_scoped_field) {
				matched_some_scoped_field = TRUE;
			}
		}
	}

	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PROHIBITED_AGENT_TYPE) {
		for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
			if (strlen(parsed_parameters->prohibited_netagent_types[i].netagent_domain) == 0 &&
			    strlen(parsed_parameters->prohibited_netagent_types[i].netagent_type) == 0) {
				break;
			}

			if (necp_ifnet_matches_agent_type(ifp, parsed_parameters->prohibited_netagent_types[i].netagent_domain, parsed_parameters->prohibited_netagent_types[i].netagent_type, TRUE)) {
				return FALSE;
			}
		}
	}

	// Checked preferred properties
	if (preferred_count) {
		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT) {
			for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
				if (uuid_is_null(parsed_parameters->preferred_netagents[i])) {
					break;
				}

				if (necp_ifnet_matches_agent(ifp, &parsed_parameters->preferred_netagents[i], TRUE)) {
					(*preferred_count)++;
					if (require_scoped_field) {
						matched_some_scoped_field = TRUE;
					}
				}
			}
		}

		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_PREFERRED_AGENT_TYPE) {
			for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
				if (strlen(parsed_parameters->preferred_netagent_types[i].netagent_domain) == 0 &&
				    strlen(parsed_parameters->preferred_netagent_types[i].netagent_type) == 0) {
					break;
				}

				if (necp_ifnet_matches_agent_type(ifp, parsed_parameters->preferred_netagent_types[i].netagent_domain, parsed_parameters->preferred_netagent_types[i].netagent_type, TRUE)) {
					(*preferred_count)++;
					if (require_scoped_field) {
						matched_some_scoped_field = TRUE;
					}
				}
			}
		}

		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT) {
			for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
				if (uuid_is_null(parsed_parameters->avoided_netagents[i])) {
					break;
				}

				if (!necp_ifnet_matches_agent(ifp, &parsed_parameters->avoided_netagents[i], TRUE)) {
					(*preferred_count)++;
				}
			}
		}

		if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_AVOIDED_AGENT_TYPE) {
			for (int i = 0; i < NECP_MAX_AGENT_PARAMETERS; i++) {
				if (strlen(parsed_parameters->avoided_netagent_types[i].netagent_domain) == 0 &&
				    strlen(parsed_parameters->avoided_netagent_types[i].netagent_type) == 0) {
					break;
				}

				if (!necp_ifnet_matches_agent_type(ifp, parsed_parameters->avoided_netagent_types[i].netagent_domain,
				    parsed_parameters->avoided_netagent_types[i].netagent_type, TRUE)) {
					(*preferred_count)++;
				}
			}
		}
	}

	if (require_scoped_field) {
		return matched_some_scoped_field;
	}

	return TRUE;
}

static bool
necp_find_matching_interface_index(struct necp_client_parsed_parameters *parsed_parameters,
    u_int *return_ifindex, bool *validate_agents)
{
	struct ifnet *ifp = NULL;
	u_int32_t best_preferred_count = 0;
	bool has_preferred_fields = FALSE;
	*return_ifindex = 0;

	if (parsed_parameters->required_interface_index != 0) {
		*return_ifindex = parsed_parameters->required_interface_index;
		return TRUE;
	}

	// Check and save off flags
	u_int32_t flags = 0;
	bool has_prohibit_flags = FALSE;
	if (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_FLAGS) {
		flags = parsed_parameters->flags;
		has_prohibit_flags = (parsed_parameters->flags &
		    (NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_EXPENSIVE |
		    NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_CONSTRAINED));
	}

	if (!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_INTERESTING_IFNET_FIELDS) &&
	    !has_prohibit_flags) {
		return TRUE;
	}

	has_preferred_fields = (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_PREFERRED_FIELDS);

	// We have interesting parameters to parse and find a matching interface
	ifnet_head_lock_shared();

	if (!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_FIELDS) &&
	    !has_preferred_fields) {
		// We do have fields to match, but they are only prohibitory
		// If the first interface in the list matches, or there are no ordered interfaces, we don't need to scope
		ifp = TAILQ_FIRST(&ifnet_ordered_head);
		if (ifp == NULL || necp_ifnet_matches_parameters(ifp, parsed_parameters, 0, NULL, false, false)) {
			// Don't set return_ifindex, so the client doesn't need to scope
			ifnet_head_done();
			return TRUE;
		}
	}

	// First check the ordered interface list
	TAILQ_FOREACH(ifp, &ifnet_ordered_head, if_ordered_link) {
		u_int32_t preferred_count = 0;
		if (necp_ifnet_matches_parameters(ifp, parsed_parameters, flags, &preferred_count, false, false)) {
			if (preferred_count > best_preferred_count ||
			    *return_ifindex == 0) {
				// Everything matched, and is most preferred. Return this interface.
				*return_ifindex = ifp->if_index;
				best_preferred_count = preferred_count;

				if (!has_preferred_fields) {
					break;
				}
			}
		}

		if (has_prohibit_flags &&
		    ifp == TAILQ_FIRST(&ifnet_ordered_head)) {
			// This was the first interface. From here on, if the
			// client prohibited either expensive or constrained,
			// don't allow either as a secondary interface option.
			flags |= (NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_EXPENSIVE |
			    NECP_CLIENT_PARAMETER_FLAG_PROHIBIT_CONSTRAINED);
		}
	}

	bool is_listener = ((parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_FLAGS) &&
	    (parsed_parameters->flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER));

	// Then check the remaining interfaces
	if ((parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_FIELDS) &&
	    ((!(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_REQUIRED_IFTYPE)) ||
	    !necp_interface_type_is_primary_eligible(parsed_parameters->required_interface_type) ||
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR) ||
	    is_listener) &&
	    (*return_ifindex == 0 || has_preferred_fields)) {
		TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
			u_int32_t preferred_count = 0;
			if (NECP_IFP_IS_ON_ORDERED_LIST(ifp)) {
				// This interface was in the ordered list, skip
				continue;
			}
			if (necp_ifnet_matches_parameters(ifp, parsed_parameters, flags, &preferred_count, false, true)) {
				if (preferred_count > best_preferred_count ||
				    *return_ifindex == 0) {
					// Everything matched, and is most preferred. Return this interface.
					*return_ifindex = ifp->if_index;
					best_preferred_count = preferred_count;

					if (!has_preferred_fields) {
						break;
					}
				}
			}
		}
	}

	ifnet_head_done();

	if (has_preferred_fields && best_preferred_count == 0 &&
	    ((parsed_parameters->valid_fields & (NECP_PARSED_PARAMETERS_SCOPED_FIELDS | NECP_PARSED_PARAMETERS_PREFERRED_FIELDS)) ==
	    (parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_PREFERRED_FIELDS))) {
		// If only has preferred ifnet fields, and nothing was found, clear the interface index and return TRUE
		*return_ifindex = 0;
		return TRUE;
	}

	if (*return_ifindex == 0 &&
	    !(parsed_parameters->valid_fields & NECP_PARSED_PARAMETERS_SCOPED_IFNET_FIELDS)) {
		// Has required fields, but not including specific interface fields. Pass for now, and check
		// to see if agents are satisfied by policy.
		*validate_agents = TRUE;
		return TRUE;
	}

	return *return_ifindex != 0;
}

#if SKYWALK

static size_t
necp_find_domain_info_common(struct necp_client *client,
    u_int8_t *parameters,
    size_t parameters_size,
    struct necp_client_flow_registration *flow_registration,    /* For logging purposes only */
    nstat_domain_info *domain_info)
{
	if (client == NULL) {
		return 0;
	}
	if (domain_info == NULL) {
		return sizeof(nstat_domain_info);
	}

	size_t offset = 0;
	u_int32_t flags = 0;
	u_int8_t *tracker_domain = NULL;
	u_int8_t *domain = NULL;

	NECP_CLIENT_FLOW_LOG(client, flow_registration, "Collecting stats");

	while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
			// If the length is larger than what can fit in the remaining parameters size, bail
			NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
			break;
		}

		if (length > 0) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_PARAMETER_FLAGS: {
					if (length >= sizeof(u_int32_t)) {
						memcpy(&flags, value, sizeof(u_int32_t));
					}

					domain_info->is_tracker =
					    !!(flags & NECP_CLIENT_PARAMETER_FLAG_KNOWN_TRACKER);
					domain_info->is_non_app_initiated =
					    !!(flags & NECP_CLIENT_PARAMETER_FLAG_NON_APP_INITIATED);
					domain_info->is_silent =
					    !!(flags & NECP_CLIENT_PARAMETER_FLAG_SILENT);
					break;
				}
				case NECP_CLIENT_PARAMETER_TRACKER_DOMAIN: {
					tracker_domain = value;
					break;
				}
				case NECP_CLIENT_PARAMETER_DOMAIN: {
					domain = value;
					break;
				}
				case NECP_CLIENT_PARAMETER_DOMAIN_OWNER: {
					strlcpy(domain_info->domain_owner, (const char *)value, sizeof(domain_info->domain_owner));
					break;
				}
				case NECP_CLIENT_PARAMETER_DOMAIN_CONTEXT: {
					strlcpy(domain_info->domain_tracker_ctxt, (const char *)value, sizeof(domain_info->domain_tracker_ctxt));
					break;
				}
				case NECP_CLIENT_PARAMETER_ATTRIBUTED_BUNDLE_IDENTIFIER: {
					strlcpy(domain_info->domain_attributed_bundle_id, (const char *)value, sizeof(domain_info->domain_attributed_bundle_id));
					break;
				}
				case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							memcpy(&domain_info->remote, &address_struct->address, sizeof(address_struct->address));
						}
					}
					break;
				}
				default: {
					break;
				}
				}
			}
		}
		offset += sizeof(struct necp_tlv_header) + length;
	}

	if (domain_info->is_tracker && tracker_domain) {
		strlcpy(domain_info->domain_name, (const char *)tracker_domain, sizeof(domain_info->domain_name));
	} else if (domain) {
		strlcpy(domain_info->domain_name, (const char *)domain, sizeof(domain_info->domain_name));
	}

	// Log if it is a known tracker
	if (domain_info->is_tracker && client) {
		NECP_CLIENT_TRACKER_LOG(client->proc_pid,
		    "Collected stats - domain <%s> owner <%s> ctxt <%s> bundle id <%s> "
		    "is_tracker %d is_non_app_initiated %d is_silent %d",
		    domain_info->domain_name[0] ? "present" : "not set",
		    domain_info->domain_owner[0] ? "present" : "not set",
		    domain_info->domain_tracker_ctxt[0] ? "present" : "not set",
		    domain_info->domain_attributed_bundle_id[0] ? "present" : "not set",
		    domain_info->is_tracker,
		    domain_info->is_non_app_initiated,
		    domain_info->is_silent);
	}

	NECP_CLIENT_FLOW_LOG(client, flow_registration,
	    "Collected stats - domain <%s> owner <%s> ctxt <%s> bundle id <%s> "
	    "is_tracker %d is_non_app_initiated %d is_silent %d",
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
necp_find_conn_extension_info(nstat_provider_context ctx,
    int requested_extension,    /* The extension to be returned */
    void *buf,                  /* If not NULL, the address for extensions to be returned in */
    size_t buf_size)            /* The size of the buffer space, typically matching the return from a previous call with a NULL buf pointer */
{
	// Note, the caller has guaranteed that any buffer has been zeroed, there is no need to clear it again

	if (ctx == NULL) {
		return 0;
	}
	struct necp_client *client = (struct necp_client *)ctx;
	switch (requested_extension) {
	case NSTAT_EXTENDED_UPDATE_TYPE_DOMAIN:
		// This is for completeness.  The intent is that domain information can be extracted at user level from the TLV parameters
		if (buf == NULL) {
			return sizeof(nstat_domain_info);
		}
		if (buf_size < sizeof(nstat_domain_info)) {
			return 0;
		}
		return necp_find_domain_info_common(client, client->parameters, client->parameters_length, NULL, (nstat_domain_info *)buf);

	case NSTAT_EXTENDED_UPDATE_TYPE_NECP_TLV:
		if (buf == NULL) {
			return client->parameters_length;
		}
		if (buf_size < client->parameters_length) {
			return 0;
		}
		memcpy(buf, client->parameters, client->parameters_length);
		return client->parameters_length;

	case NSTAT_EXTENDED_UPDATE_TYPE_ORIGINAL_NECP_TLV:
		if (buf == NULL) {
			return (client->original_parameters_source != NULL) ? client->original_parameters_source->parameters_length : 0;
		}
		if ((client->original_parameters_source == NULL) || (buf_size < client->original_parameters_source->parameters_length)) {
			return 0;
		}
		memcpy(buf, client->original_parameters_source->parameters, client->original_parameters_source->parameters_length);
		return client->original_parameters_source->parameters_length;

	case NSTAT_EXTENDED_UPDATE_TYPE_ORIGINAL_DOMAIN:
		if (buf == NULL) {
			return (client->original_parameters_source != NULL) ? sizeof(nstat_domain_info) : 0;
		}
		if ((buf_size < sizeof(nstat_domain_info)) || (client->original_parameters_source == NULL)) {
			return 0;
		}
		return necp_find_domain_info_common(client, client->original_parameters_source->parameters, client->original_parameters_source->parameters_length,
		           NULL, (nstat_domain_info *)buf);

	default:
		return 0;
	}
}

static size_t
necp_find_extension_info(userland_stats_provider_context *ctx,
    int requested_extension,    /* The extension to be returned */
    void *buf,                  /* If not NULL, the address for extensions to be returned in */
    size_t buf_size)            /* The size of the buffer space, typically matching the return from a previous call with a NULL buf pointer */
{
	if (ctx == NULL) {
		return 0;
	}
	struct necp_client_flow_registration *flow_registration = (struct necp_client_flow_registration *)(uintptr_t)ctx;
	struct necp_client *client = flow_registration->client;

	switch (requested_extension) {
	case NSTAT_EXTENDED_UPDATE_TYPE_DOMAIN:
		if (buf == NULL) {
			return sizeof(nstat_domain_info);
		}
		if (buf_size < sizeof(nstat_domain_info)) {
			return 0;
		}
		return necp_find_domain_info_common(client, client->parameters, client->parameters_length, flow_registration, (nstat_domain_info *)buf);

	case NSTAT_EXTENDED_UPDATE_TYPE_NECP_TLV:
		if (buf == NULL) {
			return client->parameters_length;
		}
		if (buf_size < client->parameters_length) {
			return 0;
		}
		memcpy(buf, client->parameters, client->parameters_length);
		return client->parameters_length;

	default:
		return 0;
	}
}

static void
necp_find_netstat_data(struct necp_client *client,
    union necp_sockaddr_union *remote,
    pid_t *effective_pid,
    uuid_t euuid,
    u_int32_t *traffic_class,
    u_int8_t *fallback_mode)
{
	size_t offset = 0;
	u_int8_t *parameters;
	u_int32_t parameters_size;

	parameters = client->parameters;
	parameters_size = (u_int32_t)client->parameters_length;

	while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
			// If the length is larger than what can fit in the remaining parameters size, bail
			NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
			break;
		}

		if (length > 0) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_PARAMETER_APPLICATION: {
					if (length >= sizeof(uuid_t)) {
						uuid_copy(euuid, value);
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PID: {
					if (length >= sizeof(pid_t)) {
						memcpy(effective_pid, value, sizeof(pid_t));
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_TRAFFIC_CLASS: {
					if (length >= sizeof(u_int32_t)) {
						memcpy(traffic_class, value, sizeof(u_int32_t));
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_FALLBACK_MODE: {
					if (length >= sizeof(u_int8_t)) {
						memcpy(fallback_mode, value, sizeof(u_int8_t));
					}
					break;
				}
				// It is an implementation quirk that the remote address can be found in the necp parameters
				// while the local address must be retrieved from the flowswitch
				case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							memcpy(remote, &address_struct->address, sizeof(address_struct->address));
						}
					}
					break;
				}
				default: {
					break;
				}
				}
			}
		}
		offset += sizeof(struct necp_tlv_header) + length;
	}
}

// Called from NetworkStatistics when it wishes to collect latest information for a TCP flow.
// It is a responsibility of NetworkStatistics to have previously zeroed any supplied memory.
static bool
necp_request_tcp_netstats(userland_stats_provider_context *ctx,
    u_int16_t *ifflagsp,
    nstat_progress_digest *digestp,
    nstat_counts *countsp,
    void *metadatap)
{
	if (ctx == NULL) {
		return false;
	}

	struct necp_client_flow_registration *flow_registration = (struct necp_client_flow_registration *)(uintptr_t)ctx;
	struct necp_client *client = flow_registration->client;
	struct necp_all_stats *ustats_kaddr = ((struct necp_all_kstats *)flow_registration->kstats_kaddr)->necp_stats_ustats;
	struct necp_tcp_stats *tcpstats = (struct necp_tcp_stats *)ustats_kaddr;
	ASSERT(tcpstats != NULL);

	u_int16_t nstat_diagnostic_flags = 0;

	// Retrieve details from the last time the assigned flows were updated
	u_int32_t route_ifindex = IFSCOPE_NONE;
	u_int16_t route_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
	u_int64_t combined_interface_details = 0;

	atomic_get_64(combined_interface_details, &flow_registration->last_interface_details);
	split_interface_details(combined_interface_details, &route_ifindex, &route_ifflags);

	if (route_ifindex == IFSCOPE_NONE) {
		// Mark no interface
		nstat_diagnostic_flags |= NSTAT_IFNET_ROUTE_VALUE_UNOBTAINABLE;
		route_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
		NECPLOG(LOG_INFO, "req tcp stats, failed to get route details for pid %d curproc %d %s\n",
		    client->proc_pid, proc_pid(current_proc()), proc_best_name(current_proc()));
	}

	if (ifflagsp) {
		*ifflagsp = route_ifflags | nstat_diagnostic_flags;
		if (tcpstats->necp_tcp_extra.flags1 & SOF1_CELLFALLBACK) {
			*ifflagsp |= NSTAT_IFNET_VIA_CELLFALLBACK;
		}
		if ((digestp == NULL) && (countsp == NULL) && (metadatap == NULL)) {
			return true;
		}
	}

	if (digestp) {
		// The digest is intended to give information that may help give insight into the state of the link
		// while avoiding the need to do the relatively expensive flowswitch lookup
		digestp->rxbytes = tcpstats->necp_tcp_counts.necp_stat_rxbytes;
		digestp->txbytes = tcpstats->necp_tcp_counts.necp_stat_txbytes;
		digestp->rxduplicatebytes = tcpstats->necp_tcp_counts.necp_stat_rxduplicatebytes;
		digestp->rxoutoforderbytes = tcpstats->necp_tcp_counts.necp_stat_rxoutoforderbytes;
		digestp->txretransmit = tcpstats->necp_tcp_counts.necp_stat_txretransmit;
		digestp->ifindex = route_ifindex;
		digestp->state = tcpstats->necp_tcp_extra.state;
		digestp->txunacked = tcpstats->necp_tcp_extra.txunacked;
		digestp->txwindow = tcpstats->necp_tcp_extra.txwindow;
		digestp->connstatus.probe_activated    = tcpstats->necp_tcp_extra.probestatus.probe_activated;
		digestp->connstatus.write_probe_failed = tcpstats->necp_tcp_extra.probestatus.write_probe_failed;
		digestp->connstatus.read_probe_failed  = tcpstats->necp_tcp_extra.probestatus.read_probe_failed;
		digestp->connstatus.conn_probe_failed  = tcpstats->necp_tcp_extra.probestatus.conn_probe_failed;

		if ((countsp == NULL) && (metadatap == NULL)) {
			return true;
		}
	}

	const struct sk_stats_flow *sf = &flow_registration->nexus_stats->fs_stats;
	if (sf == NULL) {
		nstat_diagnostic_flags |= NSTAT_IFNET_FLOWSWITCH_VALUE_UNOBTAINABLE;
		char namebuf[MAXCOMLEN + 1];
		(void) strlcpy(namebuf, "unknown", sizeof(namebuf));
		proc_name(client->proc_pid, namebuf, sizeof(namebuf));
		NECPLOG(LOG_ERR, "req tcp stats, necp_client flow_registration flow_stats missing for pid %d %s curproc %d %s\n",
		    client->proc_pid, namebuf, proc_pid(current_proc()), proc_best_name(current_proc()));
		sf = &ntstat_sk_stats_zero;
	}

	if (countsp) {
		countsp->nstat_rxbytes = tcpstats->necp_tcp_counts.necp_stat_rxbytes;
		countsp->nstat_txbytes = tcpstats->necp_tcp_counts.necp_stat_txbytes;

		countsp->nstat_rxduplicatebytes = tcpstats->necp_tcp_counts.necp_stat_rxduplicatebytes;
		countsp->nstat_rxoutoforderbytes = tcpstats->necp_tcp_counts.necp_stat_rxoutoforderbytes;
		countsp->nstat_txretransmit = tcpstats->necp_tcp_counts.necp_stat_txretransmit;

		countsp->nstat_min_rtt = tcpstats->necp_tcp_counts.necp_stat_min_rtt;
		countsp->nstat_avg_rtt = tcpstats->necp_tcp_counts.necp_stat_avg_rtt;
		countsp->nstat_var_rtt = tcpstats->necp_tcp_counts.necp_stat_var_rtt;

		countsp->nstat_connectattempts = tcpstats->necp_tcp_extra.state >= TCPS_SYN_SENT ? 1 : 0;
		countsp->nstat_connectsuccesses = tcpstats->necp_tcp_extra.state >= TCPS_ESTABLISHED ? 1 : 0;

		// Supplement what the user level has told us with what we know from the flowswitch
		countsp->nstat_rxpackets = sf->sf_ipackets;
		countsp->nstat_txpackets = sf->sf_opackets;
		if (route_ifflags & NSTAT_IFNET_IS_CELLULAR) {
			countsp->nstat_cell_rxbytes = sf->sf_ibytes;
			countsp->nstat_cell_txbytes = sf->sf_obytes;
		} else if (route_ifflags & NSTAT_IFNET_IS_WIFI) {
			countsp->nstat_wifi_rxbytes = sf->sf_ibytes;
			countsp->nstat_wifi_txbytes = sf->sf_obytes;
		} else if (route_ifflags & NSTAT_IFNET_IS_WIRED) {
			countsp->nstat_wired_rxbytes = sf->sf_ibytes;
			countsp->nstat_wired_txbytes = sf->sf_obytes;
		}
	}

	if (metadatap) {
		nstat_tcp_descriptor *desc = (nstat_tcp_descriptor *)metadatap;
		memset(desc, 0, sizeof(*desc));

		// Metadata from the flow registration
		uuid_copy(desc->fuuid, flow_registration->registration_id);

		// Metadata that the necp client should have in TLV format.
		pid_t effective_pid = client->proc_pid;
		necp_find_netstat_data(client, (union necp_sockaddr_union *)&desc->remote, &effective_pid, desc->euuid, &desc->traffic_class, &desc->fallback_mode);
		desc->epid = (u_int32_t)effective_pid;

		// Metadata from the flow registration
		// This needs to revisited if multiple flows are created from one flow registration
		struct necp_client_flow *flow = NULL;
		LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
			memcpy(&desc->local, &flow->local_addr, sizeof(desc->local));
			break;
		}

		// Metadata from the route
		desc->ifindex = route_ifindex;
		desc->ifnet_properties = route_ifflags | nstat_diagnostic_flags;
		desc->ifnet_properties |= (sf->sf_flags & SFLOWF_ONLINK) ? NSTAT_IFNET_IS_LOCAL : NSTAT_IFNET_IS_NON_LOCAL;
		if (tcpstats->necp_tcp_extra.flags1 & SOF1_CELLFALLBACK) {
			desc->ifnet_properties |= NSTAT_IFNET_VIA_CELLFALLBACK;
		}

		// Basic metadata from userland
		desc->rcvbufsize = tcpstats->necp_tcp_basic.rcvbufsize;
		desc->rcvbufused = tcpstats->necp_tcp_basic.rcvbufused;

		// Additional TCP specific data
		desc->sndbufsize = tcpstats->necp_tcp_extra.sndbufsize;
		desc->sndbufused = tcpstats->necp_tcp_extra.sndbufused;
		desc->txunacked = tcpstats->necp_tcp_extra.txunacked;
		desc->txwindow = tcpstats->necp_tcp_extra.txwindow;
		desc->txcwindow = tcpstats->necp_tcp_extra.txcwindow;
		desc->traffic_mgt_flags = tcpstats->necp_tcp_extra.traffic_mgt_flags;
		desc->state = tcpstats->necp_tcp_extra.state;

		u_int32_t cc_alg_index = tcpstats->necp_tcp_extra.cc_alg_index;
		if (cc_alg_index < TCP_CC_ALGO_COUNT) {
			strlcpy(desc->cc_algo, tcp_cc_algo_list[cc_alg_index]->name, sizeof(desc->cc_algo));
		} else {
			strlcpy(desc->cc_algo, "unknown", sizeof(desc->cc_algo));
		}

		desc->connstatus.probe_activated        = tcpstats->necp_tcp_extra.probestatus.probe_activated;
		desc->connstatus.write_probe_failed     = tcpstats->necp_tcp_extra.probestatus.write_probe_failed;
		desc->connstatus.read_probe_failed      = tcpstats->necp_tcp_extra.probestatus.read_probe_failed;
		desc->connstatus.conn_probe_failed      = tcpstats->necp_tcp_extra.probestatus.conn_probe_failed;

		memcpy(&desc->activity_bitmap, &sf->sf_activity, sizeof(sf->sf_activity));
	}

	return true;
}

// Called from NetworkStatistics when it wishes to collect latest information for a UDP flow.
static bool
necp_request_udp_netstats(userland_stats_provider_context *ctx,
    u_int16_t *ifflagsp,
    nstat_progress_digest *digestp,
    nstat_counts *countsp,
    void *metadatap)
{
#pragma unused(digestp)

	if (ctx == NULL) {
		return false;
	}

	struct necp_client_flow_registration *flow_registration = (struct necp_client_flow_registration *)(uintptr_t)ctx;
	struct necp_client *client = flow_registration->client;
	struct necp_all_stats *ustats_kaddr = ((struct necp_all_kstats *)flow_registration->kstats_kaddr)->necp_stats_ustats;
	struct necp_udp_stats *udpstats = (struct necp_udp_stats *)ustats_kaddr;
	ASSERT(udpstats != NULL);

	u_int16_t nstat_diagnostic_flags = 0;

	// Retrieve details from the last time the assigned flows were updated
	u_int32_t route_ifindex = IFSCOPE_NONE;
	u_int16_t route_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
	u_int64_t combined_interface_details = 0;

	atomic_get_64(combined_interface_details, &flow_registration->last_interface_details);
	split_interface_details(combined_interface_details, &route_ifindex, &route_ifflags);

	if (route_ifindex == IFSCOPE_NONE) {
		// Mark no interface
		nstat_diagnostic_flags |= NSTAT_IFNET_ROUTE_VALUE_UNOBTAINABLE;
		route_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
		NECPLOG(LOG_INFO, "req udp stats, failed to get route details for pid %d curproc %d %s\n",
		    client->proc_pid, proc_pid(current_proc()), proc_best_name(current_proc()));
	}

	if (ifflagsp) {
		*ifflagsp = route_ifflags | nstat_diagnostic_flags;
		if ((countsp == NULL) && (metadatap == NULL)) {
			return true;
		}
	}
	const struct sk_stats_flow *sf = &flow_registration->nexus_stats->fs_stats;
	if (sf == NULL) {
		nstat_diagnostic_flags |= NSTAT_IFNET_FLOWSWITCH_VALUE_UNOBTAINABLE;
		char namebuf[MAXCOMLEN + 1];
		(void) strlcpy(namebuf, "unknown", sizeof(namebuf));
		proc_name(client->proc_pid, namebuf, sizeof(namebuf));
		NECPLOG(LOG_ERR, "req udp stats, necp_client flow_registration flow_stats missing for pid %d %s curproc %d %s\n",
		    client->proc_pid, namebuf, proc_pid(current_proc()), proc_best_name(current_proc()));
		sf = &ntstat_sk_stats_zero;
	}

	if (countsp) {
		countsp->nstat_rxbytes = udpstats->necp_udp_counts.necp_stat_rxbytes;
		countsp->nstat_txbytes = udpstats->necp_udp_counts.necp_stat_txbytes;

		countsp->nstat_rxduplicatebytes = udpstats->necp_udp_counts.necp_stat_rxduplicatebytes;
		countsp->nstat_rxoutoforderbytes = udpstats->necp_udp_counts.necp_stat_rxoutoforderbytes;
		countsp->nstat_txretransmit = udpstats->necp_udp_counts.necp_stat_txretransmit;

		countsp->nstat_min_rtt = udpstats->necp_udp_counts.necp_stat_min_rtt;
		countsp->nstat_avg_rtt = udpstats->necp_udp_counts.necp_stat_avg_rtt;
		countsp->nstat_var_rtt = udpstats->necp_udp_counts.necp_stat_var_rtt;

		// Supplement what the user level has told us with what we know from the flowswitch
		countsp->nstat_rxpackets = sf->sf_ipackets;
		countsp->nstat_txpackets = sf->sf_opackets;
		if (route_ifflags & NSTAT_IFNET_IS_CELLULAR) {
			countsp->nstat_cell_rxbytes = sf->sf_ibytes;
			countsp->nstat_cell_txbytes = sf->sf_obytes;
		} else if (route_ifflags & NSTAT_IFNET_IS_WIFI) {
			countsp->nstat_wifi_rxbytes = sf->sf_ibytes;
			countsp->nstat_wifi_txbytes = sf->sf_obytes;
		} else if (route_ifflags & NSTAT_IFNET_IS_WIRED) {
			countsp->nstat_wired_rxbytes = sf->sf_ibytes;
			countsp->nstat_wired_txbytes = sf->sf_obytes;
		}
	}

	if (metadatap) {
		nstat_udp_descriptor *desc = (nstat_udp_descriptor *)metadatap;
		memset(desc, 0, sizeof(*desc));

		// Metadata from the flow registration
		uuid_copy(desc->fuuid, flow_registration->registration_id);

		// Metadata that the necp client should have in TLV format.
		pid_t effective_pid = client->proc_pid;
		necp_find_netstat_data(client, (union necp_sockaddr_union *)&desc->remote, &effective_pid, desc->euuid, &desc->traffic_class, &desc->fallback_mode);
		desc->epid = (u_int32_t)effective_pid;

		// Metadata from the flow registration
		// This needs to revisited if multiple flows are created from one flow registration
		struct necp_client_flow *flow = NULL;
		LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
			memcpy(&desc->local, &flow->local_addr, sizeof(desc->local));
			break;
		}

		// Metadata from the route
		desc->ifindex = route_ifindex;
		desc->ifnet_properties = route_ifflags | nstat_diagnostic_flags;

		// Basic metadata is all that is required for UDP
		desc->rcvbufsize = udpstats->necp_udp_basic.rcvbufsize;
		desc->rcvbufused = udpstats->necp_udp_basic.rcvbufused;

		memcpy(&desc->activity_bitmap, &sf->sf_activity, sizeof(sf->sf_activity));
	}

	return true;
}

// Called from NetworkStatistics when it wishes to collect latest information for a QUIC flow.
//
// TODO: For now it is an exact implementation as that of TCP.
// Still to keep the logic separate for future divergence, keeping the routines separate.
// It also seems there are lots of common code between existing implementations and
// it would be good to refactor this logic at some point.
static bool
necp_request_quic_netstats(userland_stats_provider_context *ctx,
    u_int16_t *ifflagsp,
    nstat_progress_digest *digestp,
    nstat_counts *countsp,
    void *metadatap)
{
	if (ctx == NULL) {
		return false;
	}

	struct necp_client_flow_registration *flow_registration = (struct necp_client_flow_registration *)(uintptr_t)ctx;
	struct necp_client *client = flow_registration->client;
	struct necp_all_stats *ustats_kaddr = ((struct necp_all_kstats *)flow_registration->kstats_kaddr)->necp_stats_ustats;
	struct necp_quic_stats *quicstats = (struct necp_quic_stats *)ustats_kaddr;
	ASSERT(quicstats != NULL);

	u_int16_t nstat_diagnostic_flags = 0;

	// Retrieve details from the last time the assigned flows were updated
	u_int32_t route_ifindex = IFSCOPE_NONE;
	u_int16_t route_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
	u_int64_t combined_interface_details = 0;

	atomic_get_64(combined_interface_details, &flow_registration->last_interface_details);
	split_interface_details(combined_interface_details, &route_ifindex, &route_ifflags);

	if (route_ifindex == IFSCOPE_NONE) {
		// Mark no interface
		nstat_diagnostic_flags |= NSTAT_IFNET_ROUTE_VALUE_UNOBTAINABLE;
		route_ifflags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
		NECPLOG(LOG_INFO, "req quic stats, failed to get route details for pid %d curproc %d %s\n",
		    client->proc_pid, proc_pid(current_proc()), proc_best_name(current_proc()));
	}

	if (ifflagsp) {
		*ifflagsp = route_ifflags | nstat_diagnostic_flags;
		if ((digestp == NULL) && (countsp == NULL) && (metadatap == NULL)) {
			return true;
		}
	}

	if (digestp) {
		// The digest is intended to give information that may help give insight into the state of the link
		// while avoiding the need to do the relatively expensive flowswitch lookup
		digestp->rxbytes = quicstats->necp_quic_counts.necp_stat_rxbytes;
		digestp->txbytes = quicstats->necp_quic_counts.necp_stat_txbytes;
		digestp->rxduplicatebytes = quicstats->necp_quic_counts.necp_stat_rxduplicatebytes;
		digestp->rxoutoforderbytes = quicstats->necp_quic_counts.necp_stat_rxoutoforderbytes;
		digestp->txretransmit = quicstats->necp_quic_counts.necp_stat_txretransmit;
		digestp->ifindex = route_ifindex;
		digestp->state = quicstats->necp_quic_extra.state;
		digestp->txunacked = quicstats->necp_quic_extra.txunacked;
		digestp->txwindow = quicstats->necp_quic_extra.txwindow;

		if ((countsp == NULL) && (metadatap == NULL)) {
			return true;
		}
	}

	const struct sk_stats_flow *sf = &flow_registration->nexus_stats->fs_stats;
	if (sf == NULL) {
		nstat_diagnostic_flags |= NSTAT_IFNET_FLOWSWITCH_VALUE_UNOBTAINABLE;
		char namebuf[MAXCOMLEN + 1];
		(void) strlcpy(namebuf, "unknown", sizeof(namebuf));
		proc_name(client->proc_pid, namebuf, sizeof(namebuf));
		NECPLOG(LOG_ERR, "req quic stats, necp_client flow_registration flow_stats missing for pid %d %s curproc %d %s\n",
		    client->proc_pid, namebuf, proc_pid(current_proc()), proc_best_name(current_proc()));
		sf = &ntstat_sk_stats_zero;
	}

	if (countsp) {
		countsp->nstat_rxbytes = quicstats->necp_quic_counts.necp_stat_rxbytes;
		countsp->nstat_txbytes = quicstats->necp_quic_counts.necp_stat_txbytes;

		countsp->nstat_rxduplicatebytes = quicstats->necp_quic_counts.necp_stat_rxduplicatebytes;
		countsp->nstat_rxoutoforderbytes = quicstats->necp_quic_counts.necp_stat_rxoutoforderbytes;
		countsp->nstat_txretransmit = quicstats->necp_quic_counts.necp_stat_txretransmit;

		countsp->nstat_min_rtt = quicstats->necp_quic_counts.necp_stat_min_rtt;
		countsp->nstat_avg_rtt = quicstats->necp_quic_counts.necp_stat_avg_rtt;
		countsp->nstat_var_rtt = quicstats->necp_quic_counts.necp_stat_var_rtt;

		// TODO: It would be good to expose QUIC stats for CH/SH retransmission and connection state
		// Supplement what the user level has told us with what we know from the flowswitch
		countsp->nstat_rxpackets = sf->sf_ipackets;
		countsp->nstat_txpackets = sf->sf_opackets;
		if (route_ifflags & NSTAT_IFNET_IS_CELLULAR) {
			countsp->nstat_cell_rxbytes = sf->sf_ibytes;
			countsp->nstat_cell_txbytes = sf->sf_obytes;
		} else if (route_ifflags & NSTAT_IFNET_IS_WIFI) {
			countsp->nstat_wifi_rxbytes = sf->sf_ibytes;
			countsp->nstat_wifi_txbytes = sf->sf_obytes;
		} else if (route_ifflags & NSTAT_IFNET_IS_WIRED) {
			countsp->nstat_wired_rxbytes = sf->sf_ibytes;
			countsp->nstat_wired_txbytes = sf->sf_obytes;
		}
	}

	if (metadatap) {
		nstat_quic_descriptor *desc = (nstat_quic_descriptor *)metadatap;
		memset(desc, 0, sizeof(*desc));

		// Metadata from the flow registration
		uuid_copy(desc->fuuid, flow_registration->registration_id);

		// Metadata, that the necp client should have, in TLV format.
		pid_t effective_pid = client->proc_pid;
		necp_find_netstat_data(client, (union necp_sockaddr_union *)&desc->remote, &effective_pid, desc->euuid, &desc->traffic_class, &desc->fallback_mode);
		desc->epid = (u_int32_t)effective_pid;

		// Metadata from the flow registration
		// This needs to revisited if multiple flows are created from one flow registration
		struct necp_client_flow *flow = NULL;
		LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
			memcpy(&desc->local, &flow->local_addr, sizeof(desc->local));
			break;
		}

		// Metadata from the route
		desc->ifindex = route_ifindex;
		desc->ifnet_properties = route_ifflags | nstat_diagnostic_flags;

		// Basic metadata from userland
		desc->rcvbufsize = quicstats->necp_quic_basic.rcvbufsize;
		desc->rcvbufused = quicstats->necp_quic_basic.rcvbufused;

		// Additional QUIC specific data
		desc->sndbufsize = quicstats->necp_quic_extra.sndbufsize;
		desc->sndbufused = quicstats->necp_quic_extra.sndbufused;
		desc->txunacked = quicstats->necp_quic_extra.txunacked;
		desc->txwindow = quicstats->necp_quic_extra.txwindow;
		desc->txcwindow = quicstats->necp_quic_extra.txcwindow;
		desc->traffic_mgt_flags = quicstats->necp_quic_extra.traffic_mgt_flags;
		desc->state = quicstats->necp_quic_extra.state;

		// TODO: CC algo defines should be named agnostic of the protocol
		u_int32_t cc_alg_index = quicstats->necp_quic_extra.cc_alg_index;
		if (cc_alg_index < TCP_CC_ALGO_COUNT) {
			strlcpy(desc->cc_algo, tcp_cc_algo_list[cc_alg_index]->name, sizeof(desc->cc_algo));
		} else {
			strlcpy(desc->cc_algo, "unknown", sizeof(desc->cc_algo));
		}

		memcpy(&desc->activity_bitmap, &sf->sf_activity, sizeof(sf->sf_activity));
	}
	return true;
}

// Support functions for NetworkStatistics support for necp_client connections

static void
necp_client_inherit_from_parent(
	struct necp_client *client,
	struct necp_client *parent)
{
	assert(client->original_parameters_source == NULL);

	if (parent->original_parameters_source != NULL) {
		client->original_parameters_source = parent->original_parameters_source;
	} else {
		client->original_parameters_source = parent;
	}
	necp_client_retain(client->original_parameters_source);
}

static void
necp_find_conn_netstat_data(struct necp_client *client,
    u_int32_t *ntstat_flags,
    pid_t *effective_pid,
    uuid_t puuid,
    uuid_t euuid)
{
	bool has_remote_address = false;
	bool has_ip_protocol = false;
	bool has_transport_protocol = false;
	size_t offset = 0;
	u_int8_t *parameters;
	u_int32_t parameters_size;


	parameters = client->parameters;
	parameters_size = (u_int32_t)client->parameters_length;

	while ((offset + sizeof(struct necp_tlv_header)) <= parameters_size) {
		u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
		u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

		if (length > (parameters_size - (offset + sizeof(struct necp_tlv_header)))) {
			// If the length is larger than what can fit in the remaining parameters size, bail
			NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
			break;
		}

		if (length > 0) {
			u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
			if (value != NULL) {
				switch (type) {
				case NECP_CLIENT_PARAMETER_APPLICATION: {
					if ((euuid) && (length >= sizeof(uuid_t))) {
						uuid_copy(euuid, value);
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_IP_PROTOCOL: {
					if (length >= 1) {
						has_ip_protocol = true;
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PID: {
					if ((effective_pid) && length >= sizeof(pid_t)) {
						memcpy(effective_pid, value, sizeof(pid_t));
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_PARENT_ID: {
					if ((puuid) && (length == sizeof(uuid_t))) {
						uuid_copy(puuid, value);
					}
					break;
				}
				// It is an implementation quirk that the remote address can be found in the necp parameters
				case NECP_CLIENT_PARAMETER_REMOTE_ADDRESS: {
					if (length >= sizeof(struct necp_policy_condition_addr)) {
						struct necp_policy_condition_addr *address_struct = (struct necp_policy_condition_addr *)(void *)value;
						if (necp_client_address_is_valid(&address_struct->address.sa)) {
							has_remote_address = true;
						}
					}
					break;
				}
				case NECP_CLIENT_PARAMETER_TRANSPORT_PROTOCOL: {
					if (length >= 1) {
						has_transport_protocol = true;
					}
					break;
				}
				default: {
					break;
				}
				}
			}
		}
		offset += sizeof(struct necp_tlv_header) + length;
	}
	if (ntstat_flags) {
		*ntstat_flags = (has_remote_address && has_ip_protocol && has_transport_protocol)? NSTAT_NECP_CONN_HAS_NET_ACCESS: 0;
	}
}

static bool
necp_request_conn_netstats(nstat_provider_context ctx,
    u_int32_t *ifflagsp,
    nstat_counts *countsp,
    void *metadatap)
{
	if (ctx == NULL) {
		return false;
	}
	struct necp_client *client = (struct necp_client *)(uintptr_t)ctx;
	nstat_connection_descriptor *desc = (nstat_connection_descriptor *)metadatap;

	if (ifflagsp) {
		necp_find_conn_netstat_data(client, ifflagsp, NULL, NULL, NULL);
	}
	if (countsp) {
		memset(countsp, 0, sizeof(*countsp));
	}
	if (desc) {
		memset(desc, 0, sizeof(*desc));
		// Metadata, that the necp client should have, in TLV format.
		pid_t effective_pid = client->proc_pid;
		necp_find_conn_netstat_data(client, &desc->ifnet_properties, &effective_pid, desc->puuid, desc->euuid);
		desc->epid = (u_int32_t)effective_pid;

		// User level should obtain almost all connection information from an extension
		// leaving little to do here
		uuid_copy(desc->fuuid, client->latest_flow_registration_id);
		uuid_copy(desc->cuuid, client->client_id);
	}
	return true;
}

#endif /* SKYWALK */

static int
necp_skywalk_priv_check_cred(proc_t p, kauth_cred_t cred)
{
#pragma unused(p, cred)
#if SKYWALK
	/* This includes Nexus controller and Skywalk observer privs */
	return skywalk_nxctl_check_privileges(p, cred);
#else /* !SKYWALK */
	return 0;
#endif /* !SKYWALK */
}

/// System calls

int
necp_open(struct proc *p, struct necp_open_args *uap, int *retval)
{
#pragma unused(retval)
	int error = 0;
	struct necp_fd_data *fd_data = NULL;
	struct fileproc *fp = NULL;
	int fd = -1;

	if (uap->flags & NECP_OPEN_FLAG_OBSERVER ||
	    uap->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		if (necp_skywalk_priv_check_cred(p, kauth_cred_get()) != 0 &&
		    priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0) != 0) {
			NECPLOG0(LOG_ERR, "Client does not hold necessary entitlement to observe other NECP clients");
			error = EACCES;
			goto done;
		}
	}

#if CONFIG_MACF
	error = mac_necp_check_open(p, uap->flags);
	if (error) {
		goto done;
	}
#endif /* MACF */

	error = falloc(p, &fp, &fd, vfs_context_current());
	if (error != 0) {
		goto done;
	}

	if ((fd_data = zalloc(necp_client_fd_zone)) == NULL) {
		error = ENOMEM;
		goto done;
	}

	memset(fd_data, 0, sizeof(*fd_data));

	fd_data->necp_fd_type = necp_fd_type_client;
	fd_data->flags = uap->flags;
	RB_INIT(&fd_data->clients);
	RB_INIT(&fd_data->flows);
	TAILQ_INIT(&fd_data->update_list);
	lck_mtx_init(&fd_data->fd_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);
	klist_init(&fd_data->si.si_note);
	fd_data->proc_pid = proc_pid(p);
#if SKYWALK
	LIST_INIT(&fd_data->stats_arena_list);
#endif /* !SKYWALK */

	fp->fp_flags |= FP_CLOEXEC | FP_CLOFORK;
	fp->fp_glob->fg_flag = FREAD;
	fp->fp_glob->fg_ops = &necp_fd_ops;
	fp_set_data(fp, fd_data);

	proc_fdlock(p);

	procfdtbl_releasefd(p, fd, NULL);
	fp_drop(p, fd, fp, 1);

	*retval = fd;

	if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		NECP_OBSERVER_LIST_LOCK_EXCLUSIVE();
		LIST_INSERT_HEAD(&necp_fd_observer_list, fd_data, chain);
		OSIncrementAtomic(&necp_observer_fd_count);
		NECP_OBSERVER_LIST_UNLOCK();

		// Walk all existing clients and add them
		NECP_CLIENT_TREE_LOCK_SHARED();
		struct necp_client *existing_client = NULL;
		RB_FOREACH(existing_client, _necp_client_global_tree, &necp_client_global_tree) {
			NECP_CLIENT_LOCK(existing_client);
			necp_client_update_observer_add_internal(fd_data, existing_client);
			necp_client_update_observer_update_internal(fd_data, existing_client);
			NECP_CLIENT_UNLOCK(existing_client);
		}
		NECP_CLIENT_TREE_UNLOCK();
	} else {
		NECP_FD_LIST_LOCK_EXCLUSIVE();
		LIST_INSERT_HEAD(&necp_fd_list, fd_data, chain);
		OSIncrementAtomic(&necp_client_fd_count);
		NECP_FD_LIST_UNLOCK();
	}

	proc_fdunlock(p);

done:
	if (error != 0) {
		if (fp != NULL) {
			fp_free(p, fd, fp);
			fp = NULL;
		}
		if (fd_data != NULL) {
			zfree(necp_client_fd_zone, fd_data);
			fd_data = NULL;
		}
	}

	return error;
}

// All functions called directly from necp_client_action() to handle one of the
// types should be marked with NECP_CLIENT_ACTION_FUNCTION. This ensures that
// necp_client_action() does not inline all the actions into a single function.
#define NECP_CLIENT_ACTION_FUNCTION __attribute__((noinline))

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_add(struct proc *p, struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	const size_t buffer_size = uap->buffer_size;

	if (fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER) {
		NECPLOG0(LOG_ERR, "NECP client observers with push enabled may not add their own clients");
		return EINVAL;
	}

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    buffer_size == 0 || buffer_size > NECP_MAX_CLIENT_PARAMETERS_SIZE || uap->buffer == 0) {
		return EINVAL;
	}

	client = kalloc_type(struct necp_client, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	client->parameters = kalloc_data(buffer_size, Z_WAITOK | Z_NOFAIL);
	lck_mtx_init(&client->lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);
	lck_mtx_init(&client->route_lock, &necp_fd_mtx_grp, &necp_fd_mtx_attr);

	error = copyin(uap->buffer, client->parameters, buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_add parameters copyin error (%d)", error);
		goto done;
	}

	os_ref_init(&client->reference_count, &necp_client_refgrp); // Hold our reference until close

	client->parameters_length = buffer_size;
	client->proc_pid = fd_data->proc_pid; // Save off proc pid in case the client will persist past fd
	client->agent_handle = (void *)fd_data;
	client->platform_binary = ((csproc_get_platform_binary(p) == 0) ? 0 : 1);

	necp_generate_client_id(client->client_id, false);
	LIST_INIT(&client->assertion_list);
	RB_INIT(&client->flow_registrations);

	NECP_CLIENT_LOG(client, "Adding client");

	error = copyout(client->client_id, uap->client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_add client_id copyout error (%d)", error);
		goto done;
	}

#if SKYWALK
	struct necp_client_parsed_parameters parsed_parameters = {};
	int parse_error = necp_client_parse_parameters(client, client->parameters, (u_int32_t)client->parameters_length, &parsed_parameters);

	if (parse_error == 0 &&
	    ((parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_DELEGATED_UPID) ||
	    (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_ATTRIBUTED_BUNDLE_IDENTIFIER))) {
		bool has_delegation_entitlement = (priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_SOCKET_DELEGATE, 0) == 0);
		if (!has_delegation_entitlement) {
			if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_DELEGATED_UPID) {
				NECPLOG(LOG_ERR, "%s(%d) does not hold the necessary entitlement to delegate network traffic for other processes by upid",
				    proc_name_address(p), proc_pid(p));
			}
			if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_ATTRIBUTED_BUNDLE_IDENTIFIER) {
				NECPLOG(LOG_ERR, "%s(%d) does not hold the necessary entitlement to set attributed bundle identifier",
				    proc_name_address(p), proc_pid(p));
			}
			error = EPERM;
			goto done;
		}

		if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_DELEGATED_UPID) {
			// Save off delegated unique PID
			client->delegated_upid = parsed_parameters.delegated_upid;
		}
	}

	if (parse_error == 0 && parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_INTERPOSE) {
		bool has_nexus_entitlement = (necp_skywalk_priv_check_cred(p, kauth_cred_get()) == 0);
		if (!has_nexus_entitlement) {
			NECPLOG(LOG_ERR, "%s(%d) does not hold the necessary entitlement to open a custom nexus client",
			    proc_name_address(p), proc_pid(p));
			error = EPERM;
			goto done;
		}
	}

	if (parse_error == 0 && (parsed_parameters.flags &
	    (NECP_CLIENT_PARAMETER_FLAG_CUSTOM_ETHER | NECP_CLIENT_PARAMETER_FLAG_CUSTOM_IP))) {
		bool has_custom_protocol_entitlement = (priv_check_cred(kauth_cred_get(), PRIV_NET_CUSTOM_PROTOCOL, 0) == 0);
		if (!has_custom_protocol_entitlement) {
			NECPLOG(LOG_ERR, "%s(%d) does not hold the necessary entitlement for custom protocol APIs",
			    proc_name_address(p), proc_pid(p));
			error = EPERM;
			goto done;
		}
	}

	if (parse_error == 0 && parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER &&
	    (parsed_parameters.ip_protocol == IPPROTO_TCP || parsed_parameters.ip_protocol == IPPROTO_UDP)) {
		uint32_t *netns_addr = NULL;
		uint8_t netns_addr_len = 0;
		struct ns_flow_info flow_info = {};
		uuid_copy(flow_info.nfi_flow_uuid, client->client_id);
		flow_info.nfi_protocol = parsed_parameters.ip_protocol;
		flow_info.nfi_owner_pid = client->proc_pid;
		if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID) {
			flow_info.nfi_effective_pid = parsed_parameters.effective_pid;
		} else {
			flow_info.nfi_effective_pid = flow_info.nfi_owner_pid;
		}
		proc_name(flow_info.nfi_owner_pid, flow_info.nfi_owner_name, MAXCOMLEN);
		proc_name(flow_info.nfi_effective_pid, flow_info.nfi_effective_name, MAXCOMLEN);

		if (parsed_parameters.local_addr.sa.sa_family == AF_UNSPEC) {
			// Treat no local address as a wildcard IPv6
			// parsed_parameters is already initialized to all zeros
			parsed_parameters.local_addr.sin6.sin6_family = AF_INET6;
			parsed_parameters.local_addr.sin6.sin6_len = sizeof(struct sockaddr_in6);
		}

		switch (parsed_parameters.local_addr.sa.sa_family) {
		case AF_INET: {
			memcpy(&flow_info.nfi_laddr, &parsed_parameters.local_addr.sa, parsed_parameters.local_addr.sa.sa_len);
			netns_addr = (uint32_t *)&parsed_parameters.local_addr.sin.sin_addr;
			netns_addr_len = 4;
			break;
		}
		case AF_INET6: {
			memcpy(&flow_info.nfi_laddr, &parsed_parameters.local_addr.sa, parsed_parameters.local_addr.sa.sa_len);
			netns_addr = (uint32_t *)&parsed_parameters.local_addr.sin6.sin6_addr;
			netns_addr_len = 16;
			break;
		}

		default: {
			NECPLOG(LOG_ERR, "necp_client_add listener invalid address family (%d)", parsed_parameters.local_addr.sa.sa_family);
			error = EINVAL;
			goto done;
		}
		}
		if (parsed_parameters.local_addr.sin.sin_port == 0) {
			error = netns_reserve_ephemeral(&client->port_reservation, netns_addr, netns_addr_len, parsed_parameters.ip_protocol,
			    &parsed_parameters.local_addr.sin.sin_port, NETNS_LISTENER, &flow_info);
			if (error) {
				NECPLOG(LOG_ERR, "necp_client_add netns_reserve_ephemeral error (%d)", error);
				goto done;
			}

			// Update the parameter TLVs with the assigned port
			necp_client_update_local_port_parameters(client->parameters, (u_int32_t)client->parameters_length, parsed_parameters.local_addr.sin.sin_port);
		} else {
			error = netns_reserve(&client->port_reservation, netns_addr, netns_addr_len, parsed_parameters.ip_protocol,
			    parsed_parameters.local_addr.sin.sin_port, NETNS_LISTENER, &flow_info);
			if (error) {
				NECPLOG(LOG_ERR, "necp_client_add netns_reserve error (%d)", error);
				goto done;
			}
		}
	}
	if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_PARENT_UUID) {
		// The parent "should" be found on fd_data without having to search across the whole necp_fd_list
		// It would be nice to do this a little further down where there's another instance of NECP_FD_LOCK
		// but the logic here depends on the parse paramters
		struct necp_client *parent = NULL;
		NECP_FD_LOCK(fd_data);
		parent = necp_client_fd_find_client_unlocked(fd_data, parsed_parameters.parent_uuid);
		if (parent != NULL) {
			necp_client_inherit_from_parent(client, parent);
		}
		NECP_FD_UNLOCK(fd_data);
		if (parent == NULL) {
			NECPLOG0(LOG_ERR, "necp_client_add, no necp_client_inherit_from_parent as can't find parent on fd_data");
		}
	}

#endif /* !SKYWALK */

	necp_client_update_observer_add(client);

	NECP_FD_LOCK(fd_data);
	RB_INSERT(_necp_client_tree, &fd_data->clients, client);
	OSIncrementAtomic(&necp_client_count);
	NECP_CLIENT_TREE_LOCK_EXCLUSIVE();
	RB_INSERT(_necp_client_global_tree, &necp_client_global_tree, client);
	NECP_CLIENT_TREE_UNLOCK();

	// Prime the client result
	NECP_CLIENT_LOCK(client);
	(void)necp_update_client_result(current_proc(), fd_data, client, NULL);
	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);
#if SKYWALK
	// Now everything is set, it's safe to plumb this in to NetworkStatistics
	uint32_t ntstat_properties = 0;
	necp_find_conn_netstat_data(client, &ntstat_properties, NULL, NULL, NULL);

	client->nstat_context = nstat_provider_stats_open((nstat_provider_context)client,
	    NSTAT_PROVIDER_CONN_USERLAND, (u_int64_t)ntstat_properties, necp_request_conn_netstats, necp_find_conn_extension_info);
#endif /* !SKYWALK */
done:
	if (error != 0 && client != NULL) {
		necp_client_free(client);
		client = NULL;
	}
	*retval = error;

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_claim(struct proc *p, struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t client_id = {};
	struct necp_client *client = NULL;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_claim copyin client_id error (%d)", error);
		goto done;
	}

	u_int64_t upid = proc_uniqueid(p);

	NECP_FD_LIST_LOCK_SHARED();

	struct necp_fd_data *find_fd = NULL;
	LIST_FOREACH(find_fd, &necp_fd_list, chain) {
		NECP_FD_LOCK(find_fd);
		struct necp_client *find_client = necp_client_fd_find_client_and_lock(find_fd, client_id);
		if (find_client != NULL) {
			if (find_client->delegated_upid == upid) {
				// Matched the client to claim; remove from the old fd
				client = find_client;
				RB_REMOVE(_necp_client_tree, &find_fd->clients, client);
				necp_client_retain_locked(client);
			}
			NECP_CLIENT_UNLOCK(find_client);
		}
		NECP_FD_UNLOCK(find_fd);

		if (client != NULL) {
			break;
		}
	}

	NECP_FD_LIST_UNLOCK();

	if (client == NULL) {
		error = ENOENT;
		goto done;
	}

	client->proc_pid = fd_data->proc_pid; // Transfer client to claiming pid
	client->agent_handle = (void *)fd_data;
	client->platform_binary = ((csproc_get_platform_binary(p) == 0) ? 0 : 1);

	NECP_CLIENT_LOG(client, "Claiming client");

	// Add matched client to our fd and re-run result
	NECP_FD_LOCK(fd_data);
	RB_INSERT(_necp_client_tree, &fd_data->clients, client);
	NECP_CLIENT_LOCK(client);
	(void)necp_update_client_result(current_proc(), fd_data, client, NULL);
	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);

	necp_client_release(client);

done:
	*retval = error;

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_remove(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t client_id = {};
	struct ifnet_stats_per_flow flow_ifnet_stats = {};
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_remove copyin client_id error (%d)", error);
		goto done;
	}

	if (uap->buffer != 0 && buffer_size == sizeof(flow_ifnet_stats)) {
		error = copyin(uap->buffer, &flow_ifnet_stats, buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_remove flow_ifnet_stats copyin error (%d)", error);
			// Not fatal; make sure to zero-out stats in case of partial copy
			memset(&flow_ifnet_stats, 0, sizeof(flow_ifnet_stats));
			error = 0;
		}
	} else if (uap->buffer != 0) {
		NECPLOG(LOG_ERR, "necp_client_remove unexpected parameters length (%zu)", buffer_size);
	}

	NECP_FD_LOCK(fd_data);

	pid_t pid = fd_data->proc_pid;
	struct necp_client *client = necp_client_fd_find_client_unlocked(fd_data, client_id);

	NECP_CLIENT_LOG(client, "Removing client");

	if (client != NULL) {
		// Remove any flow registrations that match
		struct necp_client_flow_registration *flow_registration = NULL;
		struct necp_client_flow_registration *temp_flow_registration = NULL;
		RB_FOREACH_SAFE(flow_registration, _necp_fd_flow_tree, &fd_data->flows, temp_flow_registration) {
			if (flow_registration->client == client) {
#if SKYWALK
				necp_destroy_flow_stats(fd_data, flow_registration, NULL, TRUE);
#endif /* SKYWALK */
				NECP_FLOW_TREE_LOCK_EXCLUSIVE();
				RB_REMOVE(_necp_client_flow_global_tree, &necp_client_flow_global_tree, flow_registration);
				NECP_FLOW_TREE_UNLOCK();
				RB_REMOVE(_necp_fd_flow_tree, &fd_data->flows, flow_registration);
			}
		}
#if SKYWALK
		if (client->nstat_context != NULL) {
			// Main path, we expect stats to be in existance at this point
			nstat_provider_stats_close(client->nstat_context);
			client->nstat_context = NULL;
		} else {
			NECPLOG0(LOG_ERR, "necp_client_remove ntstat shutdown finds nstat_context NULL");
		}
#endif /* SKYWALK */
		// Remove client from lists
		NECP_CLIENT_TREE_LOCK_EXCLUSIVE();
		RB_REMOVE(_necp_client_global_tree, &necp_client_global_tree, client);
		NECP_CLIENT_TREE_UNLOCK();
		RB_REMOVE(_necp_client_tree, &fd_data->clients, client);
	}

#if SKYWALK
	// If the currently-active arena is idle (has no more flows referring to it), or if there are defunct
	// arenas lingering in the list, schedule a threadcall to do the clean up.  The idle check is done
	// by checking if the reference count is 3: one held by this client (will be released below when we
	// destroy it) when it's non-NULL; the rest held by stats_arena_{active,list}.
	if ((fd_data->stats_arena_active != NULL && fd_data->stats_arena_active->nai_use_count == 3) ||
	    (fd_data->stats_arena_active == NULL && !LIST_EMPTY(&fd_data->stats_arena_list))) {
		uint64_t deadline = 0;
		uint64_t leeway = 0;
		clock_interval_to_deadline(necp_close_arenas_timeout_microseconds, NSEC_PER_USEC, &deadline);
		clock_interval_to_absolutetime_interval(necp_close_arenas_timeout_leeway_microseconds, NSEC_PER_USEC, &leeway);

		thread_call_enter_delayed_with_leeway(necp_close_empty_arenas_tcall, NULL,
		    deadline, leeway, THREAD_CALL_DELAY_LEEWAY);
	}
#endif /* SKYWALK */

	NECP_FD_UNLOCK(fd_data);

	if (client != NULL) {
		ASSERT(error == 0);
		necp_destroy_client(client, pid, true);
	} else {
		error = ENOENT;
		NECPLOG(LOG_ERR, "necp_client_remove invalid client_id (%d)", error);
	}
done:
	*retval = error;

	return error;
}

static struct necp_client_flow_registration *
necp_client_fd_find_flow(struct necp_fd_data *client_fd, uuid_t flow_id)
{
	NECP_FD_ASSERT_LOCKED(client_fd);
	struct necp_client_flow_registration *flow = NULL;

	if (necp_client_id_is_flow(flow_id)) {
		struct necp_client_flow_registration find;
		uuid_copy(find.registration_id, flow_id);
		flow = RB_FIND(_necp_fd_flow_tree, &client_fd->flows, &find);
	}

	return flow;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_remove_flow(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t flow_id = {};
	struct ifnet_stats_per_flow flow_ifnet_stats = {};
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_remove_flow invalid client_id (length %zu)", (size_t)uap->client_id_len);
		goto done;
	}

	error = copyin(uap->client_id, flow_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_remove_flow copyin client_id error (%d)", error);
		goto done;
	}

	if (uap->buffer != 0 && buffer_size == sizeof(flow_ifnet_stats)) {
		error = copyin(uap->buffer, &flow_ifnet_stats, buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_remove flow_ifnet_stats copyin error (%d)", error);
			// Not fatal
		}
	} else if (uap->buffer != 0) {
		NECPLOG(LOG_ERR, "necp_client_remove unexpected parameters length (%zu)", buffer_size);
	}

	NECP_FD_LOCK(fd_data);
	struct necp_client *client = NULL;
	struct necp_client_flow_registration *flow_registration = necp_client_fd_find_flow(fd_data, flow_id);
	if (flow_registration != NULL) {
#if SKYWALK
		// Cleanup stats per flow
		necp_destroy_flow_stats(fd_data, flow_registration, &flow_ifnet_stats, TRUE);
#endif /* SKYWALK */
		NECP_FLOW_TREE_LOCK_EXCLUSIVE();
		RB_REMOVE(_necp_client_flow_global_tree, &necp_client_flow_global_tree, flow_registration);
		NECP_FLOW_TREE_UNLOCK();
		RB_REMOVE(_necp_fd_flow_tree, &fd_data->flows, flow_registration);

		client = flow_registration->client;
		if (client != NULL) {
			necp_client_retain(client);
		}
	}
	NECP_FD_UNLOCK(fd_data);

	NECP_CLIENT_FLOW_LOG(client, flow_registration, "removing flow");

	if (flow_registration != NULL && client != NULL) {
		NECP_CLIENT_LOCK(client);
		if (flow_registration->client == client) {
			necp_destroy_client_flow_registration(client, flow_registration, fd_data->proc_pid, false);
		}
		necp_client_release_locked(client);
		NECP_CLIENT_UNLOCK(client);
	}

done:
	*retval = error;
	if (error != 0) {
		NECPLOG(LOG_ERR, "Remove flow error (%d)", error);
	}

	return error;
}

// Don't inline the function since it includes necp_client_parsed_parameters on the stack
static __attribute__((noinline)) int
necp_client_check_tcp_heuristics(struct necp_client *client, struct necp_client_flow *flow, u_int32_t *flags, u_int8_t *tfo_cookie, u_int8_t *tfo_cookie_len)
{
	struct necp_client_parsed_parameters parsed_parameters;
	int error = 0;

	error = necp_client_parse_parameters(client, client->parameters,
	    (u_int32_t)client->parameters_length,
	    &parsed_parameters);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_parse_parameters error (%d)", error);
		return error;
	}

	if ((flow->remote_addr.sa.sa_family != AF_INET &&
	    flow->remote_addr.sa.sa_family != AF_INET6) ||
	    (flow->local_addr.sa.sa_family != AF_INET &&
	    flow->local_addr.sa.sa_family != AF_INET6)) {
		return EINVAL;
	}

	NECP_CLIENT_ROUTE_LOCK(client);

	if (client->current_route == NULL) {
		error = ENOENT;
		goto do_unlock;
	}

	bool check_ecn = false;
	do {
		if ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_ECN_ENABLE) ==
		    NECP_CLIENT_PARAMETER_FLAG_ECN_ENABLE) {
			check_ecn = true;
			break;
		}

		if ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_ECN_DISABLE) ==
		    NECP_CLIENT_PARAMETER_FLAG_ECN_DISABLE) {
			break;
		}

		if (client->current_route != NULL) {
			if (client->current_route->rt_ifp->if_eflags & IFEF_ECN_ENABLE) {
				check_ecn = true;
				break;
			}
			if (client->current_route->rt_ifp->if_eflags & IFEF_ECN_DISABLE) {
				break;
			}
		}

		bool inbound = ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) == 0);
		if ((inbound && tcp_ecn_inbound == 1) ||
		    (!inbound && tcp_ecn_outbound == 1)) {
			check_ecn = true;
		}
	} while (false);

	if (check_ecn) {
		if (tcp_heuristic_do_ecn_with_address(client->current_route->rt_ifp,
		    (union sockaddr_in_4_6 *)&flow->local_addr)) {
			*flags |= NECP_CLIENT_RESULT_FLAG_ECN_ENABLED;
		}
	}

	if ((parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_TFO_ENABLE) ==
	    NECP_CLIENT_PARAMETER_FLAG_TFO_ENABLE) {
		if (!tcp_heuristic_do_tfo_with_address(client->current_route->rt_ifp,
		    (union sockaddr_in_4_6 *)&flow->local_addr,
		    (union sockaddr_in_4_6 *)&flow->remote_addr,
		    tfo_cookie, tfo_cookie_len)) {
			*flags |= NECP_CLIENT_RESULT_FLAG_FAST_OPEN_BLOCKED;
			*tfo_cookie_len = 0;
		}
	} else {
		*flags |= NECP_CLIENT_RESULT_FLAG_FAST_OPEN_BLOCKED;
		*tfo_cookie_len = 0;
	}
do_unlock:
	NECP_CLIENT_ROUTE_UNLOCK(client);

	return error;
}

static size_t
necp_client_calculate_flow_tlv_size(struct necp_client_flow_registration *flow_registration)
{
	size_t assigned_results_size = 0;
	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (flow->assigned) {
			size_t header_length = 0;
			if (flow->nexus) {
				header_length = sizeof(struct necp_client_nexus_flow_header);
			} else {
				header_length = sizeof(struct necp_client_flow_header);
			}
			assigned_results_size += (header_length + flow->assigned_results_length);

			if (flow->has_protoctl_event) {
				assigned_results_size += sizeof(struct necp_client_flow_protoctl_event_header);
			}
		}
	}
	return assigned_results_size;
}

static int
necp_client_fillout_flow_tlvs(struct necp_client *client,
    bool client_is_observed,
    struct necp_client_flow_registration *flow_registration,
    struct necp_client_action_args *uap,
    size_t *assigned_results_cursor)
{
	int error = 0;
	struct necp_client_flow *flow = NULL;
	LIST_FOREACH(flow, &flow_registration->flow_list, flow_chain) {
		if (flow->assigned) {
			// Write TLV headers
			struct necp_client_nexus_flow_header header = {};
			u_int32_t length = 0;
			u_int32_t flags = 0;
			u_int8_t tfo_cookie_len = 0;
			u_int8_t type = 0;

			type = NECP_CLIENT_RESULT_FLOW_ID;
			length = sizeof(header.flow_header.flow_id);
			memcpy(&header.flow_header.flow_id_tlv_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.flow_id_tlv_header.length, &length, sizeof(length));
			uuid_copy(header.flow_header.flow_id, flow_registration->registration_id);

			if (flow->nexus) {
				if (flow->check_tcp_heuristics) {
					u_int8_t tfo_cookie[NECP_TFO_COOKIE_LEN_MAX];
					tfo_cookie_len = NECP_TFO_COOKIE_LEN_MAX;

					if (necp_client_check_tcp_heuristics(client, flow, &flags,
					    tfo_cookie, &tfo_cookie_len) != 0) {
						tfo_cookie_len = 0;
					} else {
						flow->check_tcp_heuristics = FALSE;

						if (tfo_cookie_len != 0) {
							type = NECP_CLIENT_RESULT_TFO_COOKIE;
							length = tfo_cookie_len;
							memcpy(&header.tfo_cookie_tlv_header.type, &type, sizeof(type));
							memcpy(&header.tfo_cookie_tlv_header.length, &length, sizeof(length));
							memcpy(&header.tfo_cookie_value, tfo_cookie, tfo_cookie_len);
						}
					}
				}
			}

			size_t header_length = 0;
			if (flow->nexus) {
				if (tfo_cookie_len != 0) {
					header_length = sizeof(struct necp_client_nexus_flow_header) - (NECP_TFO_COOKIE_LEN_MAX - tfo_cookie_len);
				} else {
					header_length = sizeof(struct necp_client_nexus_flow_header) - sizeof(struct necp_tlv_header) - NECP_TFO_COOKIE_LEN_MAX;
				}
			} else {
				header_length = sizeof(struct necp_client_flow_header);
			}

			type = NECP_CLIENT_RESULT_FLAGS;
			length = sizeof(header.flow_header.flags_value);
			memcpy(&header.flow_header.flags_tlv_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.flags_tlv_header.length, &length, sizeof(length));
			if (flow->assigned) {
				flags |= NECP_CLIENT_RESULT_FLAG_FLOW_ASSIGNED;
			}
			if (flow->viable) {
				flags |= NECP_CLIENT_RESULT_FLAG_FLOW_VIABLE;
			}
			if (flow_registration->defunct) {
				flags |= NECP_CLIENT_RESULT_FLAG_DEFUNCT;
			}
			flags |= flow->necp_flow_flags;
			memcpy(&header.flow_header.flags_value, &flags, sizeof(flags));

			type = NECP_CLIENT_RESULT_INTERFACE;
			length = sizeof(header.flow_header.interface_value);
			memcpy(&header.flow_header.interface_tlv_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.interface_tlv_header.length, &length, sizeof(length));

			struct necp_client_result_interface interface_struct;
			interface_struct.generation = 0;
			interface_struct.index = flow->interface_index;

			memcpy(&header.flow_header.interface_value, &interface_struct, sizeof(interface_struct));
			if (flow->nexus) {
				type = NECP_CLIENT_RESULT_NETAGENT;
				length = sizeof(header.agent_value);
				memcpy(&header.agent_tlv_header.type, &type, sizeof(type));
				memcpy(&header.agent_tlv_header.length, &length, sizeof(length));

				struct necp_client_result_netagent agent_struct;
				uuid_copy(agent_struct.netagent_uuid, flow->u.nexus_agent);
				agent_struct.generation = netagent_get_generation(agent_struct.netagent_uuid);

				memcpy(&header.agent_value, &agent_struct, sizeof(agent_struct));
			}

			// Don't include outer TLV header in length field
			type = NECP_CLIENT_RESULT_FLOW;
			length = (header_length - sizeof(struct necp_tlv_header) + flow->assigned_results_length);
			if (flow->has_protoctl_event) {
				length += sizeof(struct necp_client_flow_protoctl_event_header);
			}
			memcpy(&header.flow_header.outer_header.type, &type, sizeof(type));
			memcpy(&header.flow_header.outer_header.length, &length, sizeof(length));

			error = copyout(&header, uap->buffer + client->result_length + *assigned_results_cursor, header_length);
			if (error) {
				NECPLOG(LOG_ERR, "necp_client_copy assigned results tlv_header copyout error (%d)", error);
				return error;
			}
			*assigned_results_cursor += header_length;

			if (flow->assigned_results && flow->assigned_results_length) {
				// Write inner TLVs
				error = copyout(flow->assigned_results, uap->buffer + client->result_length + *assigned_results_cursor,
				    flow->assigned_results_length);
				if (error) {
					NECPLOG(LOG_ERR, "necp_client_copy assigned results copyout error (%d)", error);
					return error;
				}
			}
			*assigned_results_cursor += flow->assigned_results_length;

			/* Read the protocol event and reset it */
			if (flow->has_protoctl_event) {
				struct necp_client_flow_protoctl_event_header protoctl_event_header = {};

				type = NECP_CLIENT_RESULT_PROTO_CTL_EVENT;
				length = sizeof(protoctl_event_header.protoctl_event);

				memcpy(&protoctl_event_header.protoctl_tlv_header.type, &type, sizeof(type));
				memcpy(&protoctl_event_header.protoctl_tlv_header.length, &length, sizeof(length));
				memcpy(&protoctl_event_header.protoctl_event, &flow->protoctl_event,
				    sizeof(flow->protoctl_event));

				error = copyout(&protoctl_event_header, uap->buffer + client->result_length + *assigned_results_cursor,
				    sizeof(protoctl_event_header));

				if (error) {
					NECPLOG(LOG_ERR, "necp_client_copy protocol control event results"
					    " tlv_header copyout error (%d)", error);
					return error;
				}
				*assigned_results_cursor += sizeof(protoctl_event_header);
				flow->has_protoctl_event = FALSE;
				flow->protoctl_event.protoctl_event_code = 0;
				flow->protoctl_event.protoctl_event_val = 0;
				flow->protoctl_event.protoctl_event_tcp_seq_num = 0;
			}
		}
	}
	if (!client_is_observed) {
		flow_registration->flow_result_read = TRUE;
	}
	return 0;
}

static int
necp_client_copy_internal(struct necp_client *client, uuid_t client_id, bool client_is_observed, struct necp_client_action_args *uap, int *retval)
{
	NECP_CLIENT_ASSERT_LOCKED(client);
	int error = 0;
	// Copy results out
	if (uap->action == NECP_CLIENT_ACTION_COPY_PARAMETERS) {
		if (uap->buffer_size < client->parameters_length) {
			return EINVAL;
		}
		error = copyout(client->parameters, uap->buffer, client->parameters_length);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy parameters copyout error (%d)", error);
			return error;
		}
		*retval = client->parameters_length;
	} else if (uap->action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT &&
	    client->result_read && client->group_members_read && !necp_client_has_unread_flows(client)) {
		// Copy updates only, but nothing to read
		// Just return 0 for bytes read
		*retval = 0;
	} else if (uap->action == NECP_CLIENT_ACTION_COPY_RESULT ||
	    uap->action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT) {
		size_t assigned_results_size = client->assigned_group_members_length;

		bool some_flow_is_defunct = false;
		struct necp_client_flow_registration *single_flow_registration = NULL;
		if (necp_client_id_is_flow(client_id)) {
			single_flow_registration = necp_client_find_flow(client, client_id);
			if (single_flow_registration != NULL) {
				assigned_results_size += necp_client_calculate_flow_tlv_size(single_flow_registration);
			}
		} else {
			// This request is for the client, so copy everything
			struct necp_client_flow_registration *flow_registration = NULL;
			RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
				if (flow_registration->defunct) {
					some_flow_is_defunct = true;
				}
				assigned_results_size += necp_client_calculate_flow_tlv_size(flow_registration);
			}
		}
		if (uap->buffer_size < (client->result_length + assigned_results_size)) {
			return EINVAL;
		}

		u_int32_t original_flags = 0;
		bool flags_updated = false;
		if (some_flow_is_defunct && client->legacy_client_is_flow) {
			// If our client expects the defunct flag in the client, add it now
			u_int32_t client_flags = 0;
			u_int32_t value_size = 0;
			u_int8_t *flags_pointer = necp_buffer_get_tlv_value(client->result, 0, &value_size);
			if (flags_pointer != NULL && value_size == sizeof(client_flags)) {
				memcpy(&client_flags, flags_pointer, value_size);
				original_flags = client_flags;
				client_flags |= NECP_CLIENT_RESULT_FLAG_DEFUNCT;
				(void)necp_buffer_write_tlv_if_different(client->result, NECP_CLIENT_RESULT_FLAGS,
				    sizeof(client_flags), &client_flags, &flags_updated,
				    client->result, sizeof(client->result));
			}
		}

		error = copyout(client->result, uap->buffer, client->result_length);

		if (flags_updated) {
			// Revert stored flags
			(void)necp_buffer_write_tlv_if_different(client->result, NECP_CLIENT_RESULT_FLAGS,
			    sizeof(original_flags), &original_flags, &flags_updated,
			    client->result, sizeof(client->result));
		}

		if (error != 0) {
			NECPLOG(LOG_ERR, "necp_client_copy result copyout error (%d)", error);
			return error;
		}

		if (client->assigned_group_members != NULL && client->assigned_group_members_length > 0) {
			error = copyout(client->assigned_group_members, uap->buffer + client->result_length, client->assigned_group_members_length);
			if (error != 0) {
				NECPLOG(LOG_ERR, "necp_client_copy group members copyout error (%d)", error);
				return error;
			}
		}

		size_t assigned_results_cursor = client->assigned_group_members_length; // Start with an offset based on the group members
		if (necp_client_id_is_flow(client_id)) {
			if (single_flow_registration != NULL) {
				error = necp_client_fillout_flow_tlvs(client, client_is_observed, single_flow_registration, uap, &assigned_results_cursor);
				if (error != 0) {
					return error;
				}
			}
		} else {
			// This request is for the client, so copy everything
			struct necp_client_flow_registration *flow_registration = NULL;
			RB_FOREACH(flow_registration, _necp_client_flow_tree, &client->flow_registrations) {
				error = necp_client_fillout_flow_tlvs(client, client_is_observed, flow_registration, uap, &assigned_results_cursor);
				if (error != 0) {
					return error;
				}
			}
		}

		*retval = client->result_length + assigned_results_cursor;

		if (!client_is_observed) {
			client->result_read = TRUE;
			client->group_members_read = TRUE;
		}
	}

	return 0;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_copy(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	uuid_clear(client_id);

	*retval = 0;

	if (uap->buffer_size == 0 || uap->buffer == 0) {
		return EINVAL;
	}

	if (uap->action != NECP_CLIENT_ACTION_COPY_PARAMETERS &&
	    uap->action != NECP_CLIENT_ACTION_COPY_RESULT &&
	    uap->action != NECP_CLIENT_ACTION_COPY_UPDATED_RESULT) {
		return EINVAL;
	}

	if (uap->client_id) {
		if (uap->client_id_len != sizeof(uuid_t)) {
			NECPLOG(LOG_ERR, "Incorrect length (got %zu, expected %zu)", (size_t)uap->client_id_len, sizeof(uuid_t));
			return ERANGE;
		}

		error = copyin(uap->client_id, client_id, sizeof(uuid_t));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy client_id copyin error (%d)", error);
			return error;
		}
	}

	const bool is_wildcard = (bool)uuid_is_null(client_id);

	NECP_FD_LOCK(fd_data);

	if (is_wildcard) {
		if (uap->action == NECP_CLIENT_ACTION_COPY_RESULT || uap->action == NECP_CLIENT_ACTION_COPY_UPDATED_RESULT) {
			struct necp_client *find_client = NULL;
			RB_FOREACH(find_client, _necp_client_tree, &fd_data->clients) {
				NECP_CLIENT_LOCK(find_client);
				if (!find_client->result_read || !find_client->group_members_read || necp_client_has_unread_flows(find_client)) {
					client = find_client;
					// Leave the client locked, and break
					break;
				}
				NECP_CLIENT_UNLOCK(find_client);
			}
		}
	} else {
		client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	}

	if (client != NULL) {
		// If client is set, it is locked
		error = necp_client_copy_internal(client, client_id, FALSE, uap, retval);
		NECP_CLIENT_UNLOCK(client);
	}

	// Unlock our own fd before moving on or returning
	NECP_FD_UNLOCK(fd_data);

	if (client == NULL) {
		if (fd_data->flags & NECP_OPEN_FLAG_OBSERVER) {
			// Observers are allowed to lookup clients on other fds

			// Lock tree
			NECP_CLIENT_TREE_LOCK_SHARED();

			bool found_client = FALSE;

			client = necp_find_client_and_lock(client_id);
			if (client != NULL) {
				// Matched, copy out data
				found_client = TRUE;
				error = necp_client_copy_internal(client, client_id, TRUE, uap, retval);
				NECP_CLIENT_UNLOCK(client);
			}

			// Unlock tree
			NECP_CLIENT_TREE_UNLOCK();

			// No client found, fail
			if (!found_client) {
				return ENOENT;
			}
		} else {
			// No client found, and not allowed to search other fds, fail
			return ENOENT;
		}
	}

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_copy_client_update(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;

	*retval = 0;

	if (!(fd_data->flags & NECP_OPEN_FLAG_PUSH_OBSERVER)) {
		NECPLOG0(LOG_ERR, "NECP fd is not observer, cannot copy client update");
		return EINVAL;
	}

	if (uap->client_id_len != sizeof(uuid_t) || uap->client_id == 0) {
		NECPLOG0(LOG_ERR, "Client id invalid, cannot copy client update");
		return EINVAL;
	}

	if (uap->buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "Buffer invalid, cannot copy client update");
		return EINVAL;
	}

	NECP_FD_LOCK(fd_data);
	struct necp_client_update *client_update = TAILQ_FIRST(&fd_data->update_list);
	if (client_update != NULL) {
		TAILQ_REMOVE(&fd_data->update_list, client_update, chain);
		VERIFY(fd_data->update_count > 0);
		fd_data->update_count--;
	}
	NECP_FD_UNLOCK(fd_data);

	if (client_update != NULL) {
		error = copyout(client_update->client_id, uap->client_id, sizeof(uuid_t));
		if (error) {
			NECPLOG(LOG_ERR, "Copy client update copyout client id error (%d)", error);
		} else {
			if (uap->buffer_size < client_update->update_length) {
				NECPLOG(LOG_ERR, "Buffer size cannot hold update (%zu < %zu)", (size_t)uap->buffer_size, client_update->update_length);
				error = EINVAL;
			} else {
				error = copyout(client_update->update, uap->buffer, client_update->update_length);
				if (error) {
					NECPLOG(LOG_ERR, "Copy client update copyout error (%d)", error);
				} else {
					*retval = client_update->update_length;
				}
			}
		}

		necp_client_update_free(client_update);
		client_update = NULL;
	} else {
		error = ENOENT;
	}

	return error;
}

static int
necp_client_copy_parameters_locked(struct necp_client *client,
    struct necp_client_nexus_parameters *parameters)
{
	VERIFY(parameters != NULL);

	struct necp_client_parsed_parameters parsed_parameters = {};
	int error = necp_client_parse_parameters(client, client->parameters, (u_int32_t)client->parameters_length, &parsed_parameters);

	parameters->pid = client->proc_pid;
	if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_EFFECTIVE_PID) {
		parameters->epid = parsed_parameters.effective_pid;
	} else {
		parameters->epid = parameters->pid;
	}
#if SKYWALK
	parameters->port_reservation = client->port_reservation;
#endif /* !SKYWALK */
	memcpy(&parameters->local_addr, &parsed_parameters.local_addr, sizeof(parameters->local_addr));
	memcpy(&parameters->remote_addr, &parsed_parameters.remote_addr, sizeof(parameters->remote_addr));
	parameters->ip_protocol = parsed_parameters.ip_protocol;
	if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_TRANSPORT_PROTOCOL) {
		parameters->transport_protocol = parsed_parameters.transport_protocol;
	} else {
		parameters->transport_protocol = parsed_parameters.ip_protocol;
	}
	parameters->ethertype = parsed_parameters.ethertype;
	parameters->traffic_class = parsed_parameters.traffic_class;
	if (uuid_is_null(client->override_euuid)) {
		uuid_copy(parameters->euuid, parsed_parameters.effective_uuid);
	} else {
		uuid_copy(parameters->euuid, client->override_euuid);
	}
	parameters->is_listener = (parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_LISTENER) ? 1 : 0;
	parameters->is_interpose = (parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_INTERPOSE) ? 1 : 0;
	parameters->is_custom_ether = (parsed_parameters.flags & NECP_CLIENT_PARAMETER_FLAG_CUSTOM_ETHER) ? 1 : 0;
	parameters->policy_id = client->policy_id;

	// parse client result flag
	u_int32_t client_result_flags = 0;
	u_int32_t value_size = 0;
	u_int8_t *flags_pointer = NULL;
	flags_pointer = necp_buffer_get_tlv_value(client->result, 0, &value_size);
	if (flags_pointer && value_size == sizeof(client_result_flags)) {
		memcpy(&client_result_flags, flags_pointer, value_size);
	}
	parameters->allow_qos_marking = (client_result_flags & NECP_CLIENT_RESULT_FLAG_ALLOW_QOS_MARKING) ? 1 : 0;

	if (parsed_parameters.valid_fields & NECP_PARSED_PARAMETERS_FIELD_LOCAL_ADDR_PREFERENCE) {
		if (parsed_parameters.local_address_preference == NECP_CLIENT_PARAMETER_LOCAL_ADDRESS_PREFERENCE_DEFAULT) {
			parameters->override_address_selection = false;
		} else if (parsed_parameters.local_address_preference == NECP_CLIENT_PARAMETER_LOCAL_ADDRESS_PREFERENCE_TEMPORARY) {
			parameters->override_address_selection = true;
			parameters->use_stable_address = false;
		} else if (parsed_parameters.local_address_preference == NECP_CLIENT_PARAMETER_LOCAL_ADDRESS_PREFERENCE_STABLE) {
			parameters->override_address_selection = true;
			parameters->use_stable_address = true;
		}
	} else {
		parameters->override_address_selection = false;
	}

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_list(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *find_client = NULL;
	uuid_t *list = NULL;
	u_int32_t requested_client_count = 0;
	u_int32_t client_count = 0;
	size_t copy_buffer_size = 0;

	if (uap->buffer_size < sizeof(requested_client_count) || uap->buffer == 0) {
		error = EINVAL;
		goto done;
	}

	if (!(fd_data->flags & NECP_OPEN_FLAG_OBSERVER)) {
		NECPLOG0(LOG_ERR, "Client does not hold necessary entitlement to list other NECP clients");
		error = EACCES;
		goto done;
	}

	error = copyin(uap->buffer, &requested_client_count, sizeof(requested_client_count));
	if (error) {
		goto done;
	}

	if (os_mul_overflow(sizeof(uuid_t), requested_client_count, &copy_buffer_size)) {
		error = ERANGE;
		goto done;
	}

	if (uap->buffer_size - sizeof(requested_client_count) != copy_buffer_size) {
		error = EINVAL;
		goto done;
	}

	if (copy_buffer_size > NECP_MAX_CLIENT_LIST_SIZE) {
		error = EINVAL;
		goto done;
	}

	if (requested_client_count > 0) {
		if ((list = (uuid_t*)kalloc_data(copy_buffer_size, Z_WAITOK | Z_ZERO)) == NULL) {
			error = ENOMEM;
			goto done;
		}
	}

	// Lock tree
	NECP_CLIENT_TREE_LOCK_SHARED();

	find_client = NULL;
	RB_FOREACH(find_client, _necp_client_global_tree, &necp_client_global_tree) {
		NECP_CLIENT_LOCK(find_client);
		if (!uuid_is_null(find_client->client_id)) {
			if (client_count < requested_client_count) {
				uuid_copy(list[client_count], find_client->client_id);
			}
			client_count++;
		}
		NECP_CLIENT_UNLOCK(find_client);
	}

	// Unlock tree
	NECP_CLIENT_TREE_UNLOCK();

	error = copyout(&client_count, uap->buffer, sizeof(client_count));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_list buffer copyout error (%d)", error);
		goto done;
	}

	if (requested_client_count > 0 &&
	    client_count > 0 &&
	    list != NULL) {
		error = copyout(list, uap->buffer + sizeof(client_count), copy_buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_list client count copyout error (%d)", error);
			goto done;
		}
	}
done:
	if (list != NULL) {
		kfree_data(list, copy_buffer_size);
	}
	*retval = error;

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_add_flow(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	struct necp_client_nexus_parameters parameters = {};
	struct proc *proc = PROC_NULL;
	struct necp_client_add_flow *add_request = NULL;
	struct necp_client_add_flow *allocated_add_request = NULL;
	struct necp_client_add_flow_default default_add_request = {};
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_add_flow invalid client_id (length %zu)", (size_t)uap->client_id_len);
		goto done;
	}

	if (uap->buffer == 0 || buffer_size < sizeof(struct necp_client_add_flow) ||
	    buffer_size > sizeof(struct necp_client_add_flow_default) * 4) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_add_flow invalid buffer (length %zu)", buffer_size);
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_add_flow copyin client_id error (%d)", error);
		goto done;
	}

	if (buffer_size <= sizeof(struct necp_client_add_flow_default)) {
		// Fits in default size
		error = copyin(uap->buffer, &default_add_request, buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_add_flow copyin default_add_request error (%d)", error);
			goto done;
		}

		add_request = (struct necp_client_add_flow *)&default_add_request;
	} else {
		allocated_add_request = (struct necp_client_add_flow *)kalloc_data(buffer_size, Z_WAITOK | Z_ZERO);
		if (allocated_add_request == NULL) {
			error = ENOMEM;
			goto done;
		}

		error = copyin(uap->buffer, allocated_add_request, buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_add_flow copyin default_add_request error (%d)", error);
			goto done;
		}

		add_request = allocated_add_request;
	}

	NECP_FD_LOCK(fd_data);
	pid_t pid = fd_data->proc_pid;
	proc = proc_find(pid);
	if (proc == PROC_NULL) {
		NECP_FD_UNLOCK(fd_data);
		NECPLOG(LOG_ERR, "necp_client_add_flow process not found for pid %d error (%d)", pid, error);
		error = ESRCH;
		goto done;
	}

	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client == NULL) {
		error = ENOENT;
		NECP_FD_UNLOCK(fd_data);
		goto done;
	}

	// Using ADD_FLOW indicates that the client supports multiple flows per client
	client->legacy_client_is_flow = false;

	necp_client_retain_locked(client);
	necp_client_copy_parameters_locked(client, &parameters);

	struct necp_client_flow_registration *new_registration = necp_client_create_flow_registration(fd_data, client);
	if (new_registration == NULL) {
		error = ENOMEM;
		NECP_CLIENT_UNLOCK(client);
		NECP_FD_UNLOCK(fd_data);
		NECPLOG0(LOG_ERR, "Failed to allocate flow registration");
		goto done;
	}

	new_registration->flags = add_request->flags;

	// Copy new ID out to caller
	uuid_copy(add_request->registration_id, new_registration->registration_id);

	NECP_CLIENT_FLOW_LOG(client, new_registration, "adding flow");

	// Copy override address
	if (add_request->flags & NECP_CLIENT_FLOW_FLAGS_OVERRIDE_ADDRESS) {
		size_t offset_of_address = (sizeof(struct necp_client_add_flow) +
		    add_request->stats_request_count * sizeof(struct necp_client_flow_stats));
		if (buffer_size >= offset_of_address + sizeof(struct sockaddr_in)) {
			struct sockaddr *override_address = (struct sockaddr *)(((uint8_t *)add_request) + offset_of_address);
			if (buffer_size >= offset_of_address + override_address->sa_len &&
			    override_address->sa_len <= sizeof(parameters.remote_addr)) {
				memcpy(&parameters.remote_addr, override_address, override_address->sa_len);
			}
		}
	}

#if SKYWALK
	if (add_request->flags & NECP_CLIENT_FLOW_FLAGS_ALLOW_NEXUS) {
		void *assigned_results = NULL;
		size_t assigned_results_length = 0;
		uint32_t interface_index = 0;

		// Validate that the nexus UUID is assigned
		bool found_nexus = false;
		for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
			if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
				struct necp_client_interface_option *option = &client->interface_options[option_i];
				if (uuid_compare(option->nexus_agent, add_request->agent_uuid) == 0) {
					interface_index = option->interface_index;
					found_nexus = true;
					break;
				}
			} else {
				struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
				if (uuid_compare(option->nexus_agent, add_request->agent_uuid) == 0) {
					interface_index = option->interface_index;
					found_nexus = true;
					break;
				}
			}
		}

		if (!found_nexus) {
			NECPLOG0(LOG_ERR, "Requested nexus not found");
		} else {
			necp_client_add_nexus_flow_if_needed(new_registration, add_request->agent_uuid, interface_index);

			error = netagent_client_message_with_params(add_request->agent_uuid,
			    ((new_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
			    client->client_id :
			    new_registration->registration_id),
			    pid, client->agent_handle,
			    NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS,
			    (struct necp_client_agent_parameters *)&parameters,
			    &assigned_results, &assigned_results_length);
			if (error != 0) {
				VERIFY(assigned_results == NULL);
				VERIFY(assigned_results_length == 0);
				NECPLOG(LOG_ERR, "netagent_client_message error (%d)", error);
			} else if (assigned_results != NULL) {
				if (!necp_assign_client_result_locked(proc, fd_data, client, new_registration, add_request->agent_uuid,
				    assigned_results, assigned_results_length, false)) {
					kfree_data(assigned_results, assigned_results_length);
				}
			}
		}
	}

	// Don't request stats if nexus creation fails
	if (error == 0 && add_request->stats_request_count > 0 && necp_arena_initialize(fd_data, true) == 0) {
		struct necp_client_flow_stats *stats_request = (struct necp_client_flow_stats *)&add_request->stats_requests[0];
		struct necp_stats_bufreq bufreq = {};

		NECP_CLIENT_FLOW_LOG(client, new_registration, "Initializing stats");

		bufreq.necp_stats_bufreq_id = NECP_CLIENT_STATISTICS_BUFREQ_ID;
		bufreq.necp_stats_bufreq_type = stats_request->stats_type;
		bufreq.necp_stats_bufreq_ver = stats_request->stats_version;
		bufreq.necp_stats_bufreq_size = stats_request->stats_size;
		bufreq.necp_stats_bufreq_uaddr = stats_request->stats_addr;
		(void)necp_stats_initialize(fd_data, client, new_registration, &bufreq);
		stats_request->stats_type = bufreq.necp_stats_bufreq_type;
		stats_request->stats_version = bufreq.necp_stats_bufreq_ver;
		stats_request->stats_size = bufreq.necp_stats_bufreq_size;
		stats_request->stats_addr = bufreq.necp_stats_bufreq_uaddr;
	}
#endif /* !SKYWALK */

	if (error == 0 &&
	    (add_request->flags & NECP_CLIENT_FLOW_FLAGS_BROWSE ||
	    add_request->flags & NECP_CLIENT_FLOW_FLAGS_RESOLVE)) {
		uint32_t interface_index = IFSCOPE_NONE;
		ifnet_head_lock_shared();
		struct ifnet *interface = NULL;
		TAILQ_FOREACH(interface, &ifnet_head, if_link) {
			ifnet_lock_shared(interface);
			if (interface->if_agentids != NULL) {
				for (u_int32_t i = 0; i < interface->if_agentcount; i++) {
					if (uuid_compare(interface->if_agentids[i], add_request->agent_uuid) == 0) {
						interface_index = interface->if_index;
						break;
					}
				}
			}
			ifnet_lock_done(interface);
			if (interface_index != IFSCOPE_NONE) {
				break;
			}
		}
		ifnet_head_done();

		necp_client_add_nexus_flow_if_needed(new_registration, add_request->agent_uuid, interface_index);

		error = netagent_client_message_with_params(add_request->agent_uuid,
		    ((new_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
		    client->client_id :
		    new_registration->registration_id),
		    pid, client->agent_handle,
		    NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT,
		    (struct necp_client_agent_parameters *)&parameters,
		    NULL, NULL);
		if (error != 0) {
			NECPLOG(LOG_ERR, "netagent_client_message error (%d)", error);
		}
	}

	if (error != 0) {
		// Encountered an error in adding the flow, destroy the flow registration
#if SKYWALK
		necp_destroy_flow_stats(fd_data, new_registration, NULL, false);
#endif /* SKYWALK */
		NECP_FLOW_TREE_LOCK_EXCLUSIVE();
		RB_REMOVE(_necp_client_flow_global_tree, &necp_client_flow_global_tree, new_registration);
		NECP_FLOW_TREE_UNLOCK();
		RB_REMOVE(_necp_fd_flow_tree, &fd_data->flows, new_registration);
		necp_destroy_client_flow_registration(client, new_registration, fd_data->proc_pid, true);
		new_registration = NULL;
	}

	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);

	necp_client_release(client);

	if (error != 0) {
		goto done;
	}

	// Copy the request back out to the caller with assigned fields
	error = copyout(add_request, uap->buffer, buffer_size);
	if (error != 0) {
		NECPLOG(LOG_ERR, "necp_client_add_flow copyout add_request error (%d)", error);
	}

done:
	*retval = error;
	if (error != 0) {
		NECPLOG(LOG_ERR, "Add flow error (%d)", error);
	}

	if (allocated_add_request != NULL) {
		kfree_data(allocated_add_request, buffer_size);
	}

	if (proc != PROC_NULL) {
		proc_rele(proc);
	}
	return error;
}

#if SKYWALK

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_request_nexus(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	struct necp_client_nexus_parameters parameters = {};
	struct proc *proc = PROC_NULL;
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_request_nexus copyin client_id error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	pid_t pid = fd_data->proc_pid;
	proc = proc_find(pid);
	if (proc == PROC_NULL) {
		NECP_FD_UNLOCK(fd_data);
		NECPLOG(LOG_ERR, "necp_client_request_nexus process not found for pid %d error (%d)", pid, error);
		error = ESRCH;
		goto done;
	}

	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client == NULL) {
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
		goto done;
	}

	// Using REQUEST_NEXUS indicates that the client only supports one flow per client
	client->legacy_client_is_flow = true;

	necp_client_retain_locked(client);
	necp_client_copy_parameters_locked(client, &parameters);

	do {
		void *assigned_results = NULL;
		size_t assigned_results_length = 0;
		uuid_t nexus_uuid;
		uint32_t interface_index = 0;

		// Validate that the nexus UUID is assigned
		bool found_nexus = false;
		for (u_int32_t option_i = 0; option_i < client->interface_option_count; option_i++) {
			if (option_i < NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT) {
				struct necp_client_interface_option *option = &client->interface_options[option_i];
				if (!uuid_is_null(option->nexus_agent)) {
					uuid_copy(nexus_uuid, option->nexus_agent);
					interface_index = option->interface_index;
					found_nexus = true;
					break;
				}
			} else {
				struct necp_client_interface_option *option = &client->extra_interface_options[option_i - NECP_CLIENT_INTERFACE_OPTION_STATIC_COUNT];
				if (!uuid_is_null(option->nexus_agent)) {
					uuid_copy(nexus_uuid, option->nexus_agent);
					interface_index = option->interface_index;
					found_nexus = true;
					break;
				}
			}
		}

		if (!found_nexus) {
			NECP_CLIENT_UNLOCK(client);
			NECP_FD_UNLOCK(fd_data);
			necp_client_release(client);
			// Break the loop
			error = ENETDOWN;
			goto done;
		}

		struct necp_client_flow_registration *new_registration = necp_client_create_flow_registration(fd_data, client);
		if (new_registration == NULL) {
			error = ENOMEM;
			NECP_CLIENT_UNLOCK(client);
			NECP_FD_UNLOCK(fd_data);
			necp_client_release(client);
			NECPLOG0(LOG_ERR, "Failed to allocate flow registration");
			goto done;
		}

		new_registration->flags = (NECP_CLIENT_FLOW_FLAGS_ALLOW_NEXUS | NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID);

		necp_client_add_nexus_flow_if_needed(new_registration, nexus_uuid, interface_index);

		// Note: Any clients using "request_nexus" are not flow-registration aware.
		// Register the Client ID rather than the Registration ID with the nexus, since
		// the client will send traffic based on the client ID.
		error = netagent_client_message_with_params(nexus_uuid,
		    ((new_registration->flags & NECP_CLIENT_FLOW_FLAGS_USE_CLIENT_ID) ?
		    client->client_id :
		    new_registration->registration_id),
		    pid, client->agent_handle,
		    NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS,
		    (struct necp_client_agent_parameters *)&parameters,
		    &assigned_results, &assigned_results_length);
		if (error) {
			NECP_CLIENT_UNLOCK(client);
			NECP_FD_UNLOCK(fd_data);
			necp_client_release(client);
			VERIFY(assigned_results == NULL);
			VERIFY(assigned_results_length == 0);
			NECPLOG(LOG_ERR, "netagent_client_message error (%d)", error);
			goto done;
		}

		if (assigned_results != NULL) {
			if (!necp_assign_client_result_locked(proc, fd_data, client, new_registration, nexus_uuid,
			    assigned_results, assigned_results_length, false)) {
				kfree_data(assigned_results, assigned_results_length);
			}
		}

		if (uap->buffer != 0 && buffer_size == sizeof(struct necp_stats_bufreq) &&
		    necp_arena_initialize(fd_data, true) == 0) {
			struct necp_stats_bufreq bufreq = {};
			int copy_error = copyin(uap->buffer, &bufreq, buffer_size);
			if (copy_error) {
				NECPLOG(LOG_ERR, "necp_client_request_nexus copyin bufreq error (%d)", copy_error);
			} else {
				(void)necp_stats_initialize(fd_data, client, new_registration, &bufreq);
				copy_error = copyout(&bufreq, uap->buffer, buffer_size);
				if (copy_error != 0) {
					NECPLOG(LOG_ERR, "necp_client_request_nexus copyout bufreq error (%d)", copy_error);
				}
			}
		}
	} while (false);

	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);

	necp_client_release(client);

done:
	*retval = error;
	if (error != 0) {
		NECPLOG(LOG_ERR, "Request nexus error (%d)", error);
	}

	if (proc != PROC_NULL) {
		proc_rele(proc);
	}
	return error;
}
#endif /* !SKYWALK */

static void
necp_client_add_assertion(struct necp_client *client, uuid_t netagent_uuid)
{
	struct necp_client_assertion *new_assertion = NULL;

	new_assertion = kalloc_type(struct necp_client_assertion,
	    Z_WAITOK | Z_NOFAIL);

	uuid_copy(new_assertion->asserted_netagent, netagent_uuid);

	LIST_INSERT_HEAD(&client->assertion_list, new_assertion, assertion_chain);
}

static bool
necp_client_remove_assertion(struct necp_client *client, uuid_t netagent_uuid)
{
	struct necp_client_assertion *found_assertion = NULL;
	struct necp_client_assertion *search_assertion = NULL;
	LIST_FOREACH(search_assertion, &client->assertion_list, assertion_chain) {
		if (uuid_compare(search_assertion->asserted_netagent, netagent_uuid) == 0) {
			found_assertion = search_assertion;
			break;
		}
	}

	if (found_assertion == NULL) {
		NECPLOG0(LOG_ERR, "Netagent uuid not previously asserted");
		return false;
	}

	LIST_REMOVE(found_assertion, assertion_chain);
	kfree_type(struct necp_client_assertion, found_assertion);
	return true;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_agent_action(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	bool acted_on_agent = FALSE;
	u_int8_t *parameters = NULL;
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_agent_action invalid parameters");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_agent_action copyin client_id error (%d)", error);
		goto done;
	}

	if (buffer_size > NECP_MAX_AGENT_ACTION_SIZE) {
		NECPLOG(LOG_ERR, "necp_client_agent_action invalid buffer size (>%u)", NECP_MAX_AGENT_ACTION_SIZE);
		error = EINVAL;
		goto done;
	}

	if ((parameters = (u_int8_t *)kalloc_data(buffer_size, Z_WAITOK | Z_ZERO)) == NULL) {
		NECPLOG0(LOG_ERR, "necp_client_agent_action malloc failed");
		error = ENOMEM;
		goto done;
	}

	error = copyin(uap->buffer, parameters, buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_agent_action parameters copyin error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client != NULL) {
		size_t offset = 0;
		while ((offset + sizeof(struct necp_tlv_header)) <= buffer_size) {
			u_int8_t type = necp_buffer_get_tlv_type(parameters, offset);
			u_int32_t length = necp_buffer_get_tlv_length(parameters, offset);

			if (length > (buffer_size - (offset + sizeof(struct necp_tlv_header)))) {
				// If the length is larger than what can fit in the remaining parameters size, bail
				NECPLOG(LOG_ERR, "Invalid TLV length (%u)", length);
				break;
			}

			if (length >= sizeof(uuid_t)) {
				u_int8_t *value = necp_buffer_get_tlv_value(parameters, offset, NULL);
				if (value == NULL) {
					NECPLOG0(LOG_ERR, "Invalid TLV value");
					break;
				}
				if (type == NECP_CLIENT_PARAMETER_TRIGGER_AGENT ||
				    type == NECP_CLIENT_PARAMETER_ASSERT_AGENT ||
				    type == NECP_CLIENT_PARAMETER_UNASSERT_AGENT) {
					uuid_t agent_uuid;
					uuid_copy(agent_uuid, value);
					u_int8_t netagent_message_type = 0;
					if (type == NECP_CLIENT_PARAMETER_TRIGGER_AGENT) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER;
					} else if (type == NECP_CLIENT_PARAMETER_ASSERT_AGENT) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT;
					} else if (type == NECP_CLIENT_PARAMETER_UNASSERT_AGENT) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT;
					}

					// Before unasserting, verify that the assertion was already taken
					if (type == NECP_CLIENT_PARAMETER_UNASSERT_AGENT) {
						if (!necp_client_remove_assertion(client, agent_uuid)) {
							error = ENOENT;
							break;
						}
					}

					struct necp_client_nexus_parameters parsed_parameters = {};
					necp_client_copy_parameters_locked(client, &parsed_parameters);

					error = netagent_client_message_with_params(agent_uuid,
					    client_id,
					    fd_data->proc_pid,
					    client->agent_handle,
					    netagent_message_type,
					    (struct necp_client_agent_parameters *)&parsed_parameters,
					    NULL, NULL);
					if (error == 0) {
						acted_on_agent = TRUE;
					} else {
						break;
					}

					// Only save the assertion if the action succeeded
					if (type == NECP_CLIENT_PARAMETER_ASSERT_AGENT) {
						necp_client_add_assertion(client, agent_uuid);
					}
				} else if (type == NECP_CLIENT_PARAMETER_AGENT_ADD_GROUP_MEMBERS ||
				    type == NECP_CLIENT_PARAMETER_AGENT_REMOVE_GROUP_MEMBERS) {
					uuid_t agent_uuid;
					uuid_copy(agent_uuid, value);
					u_int8_t netagent_message_type = 0;
					if (type == NECP_CLIENT_PARAMETER_AGENT_ADD_GROUP_MEMBERS) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_ADD_GROUP_MEMBERS;
					} else if (type == NECP_CLIENT_PARAMETER_AGENT_REMOVE_GROUP_MEMBERS) {
						netagent_message_type = NETAGENT_MESSAGE_TYPE_REMOVE_GROUP_MEMBERS;
					}

					struct necp_client_group_members group_members = {};
					group_members.group_members_length = (length - sizeof(uuid_t));
					group_members.group_members = (value + sizeof(uuid_t));
					error = netagent_client_message_with_params(agent_uuid,
					    client_id,
					    fd_data->proc_pid,
					    client->agent_handle,
					    netagent_message_type,
					    (struct necp_client_agent_parameters *)&group_members,
					    NULL, NULL);
					if (error == 0) {
						acted_on_agent = TRUE;
					} else {
						break;
					}
				} else if (type == NECP_CLIENT_PARAMETER_REPORT_AGENT_ERROR) {
					uuid_t agent_uuid;
					uuid_copy(agent_uuid, value);
					struct necp_client_agent_parameters agent_params = {};
					if ((length - sizeof(uuid_t)) >= sizeof(agent_params.u.error)) {
						memcpy(&agent_params.u.error,
						    (value + sizeof(uuid_t)),
						    sizeof(agent_params.u.error));
					}
					error = netagent_client_message_with_params(agent_uuid,
					    client_id,
					    fd_data->proc_pid,
					    client->agent_handle,
					    NETAGENT_MESSAGE_TYPE_CLIENT_ERROR,
					    &agent_params,
					    NULL, NULL);
					if (error == 0) {
						acted_on_agent = TRUE;
					} else {
						break;
					}
				}
			}

			offset += sizeof(struct necp_tlv_header) + length;
		}

		NECP_CLIENT_UNLOCK(client);
	}
	NECP_FD_UNLOCK(fd_data);

	if (!acted_on_agent &&
	    error == 0) {
		error = ENOENT;
	}
done:
	*retval = error;
	if (parameters != NULL) {
		kfree_data(parameters, buffer_size);
		parameters = NULL;
	}

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_copy_agent(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t agent_uuid;
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_agent bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, agent_uuid, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_agent copyin agent_uuid error (%d)", error);
		goto done;
	}

	error = netagent_copyout(agent_uuid, uap->buffer, buffer_size);
	if (error) {
		// netagent_copyout already logs appropriate errors
		goto done;
	}
done:
	*retval = error;

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_agent_use(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;
	struct necp_agent_use_parameters parameters = {};
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    buffer_size != sizeof(parameters) || uap->buffer == 0) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "Copyin client_id error (%d)", error);
		goto done;
	}

	error = copyin(uap->buffer, &parameters, buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "Parameters copyin error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client != NULL) {
		error = netagent_use(parameters.agent_uuid, &parameters.out_use_count);
		NECP_CLIENT_UNLOCK(client);
	} else {
		error = ENOENT;
	}

	NECP_FD_UNLOCK(fd_data);

	if (error == 0) {
		error = copyout(&parameters, uap->buffer, buffer_size);
		if (error) {
			NECPLOG(LOG_ERR, "Parameters copyout error (%d)", error);
			goto done;
		}
	}

done:
	*retval = error;

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_acquire_agent_token(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	uuid_t agent_uuid = {};
	const size_t buffer_size = uap->buffer_size;

	*retval = 0;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    buffer_size == 0 || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_agent bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, agent_uuid, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_agent copyin agent_uuid error (%d)", error);
		goto done;
	}

	error = netagent_acquire_token(agent_uuid, uap->buffer, buffer_size, retval);
done:
	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_copy_interface(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	u_int32_t interface_index = 0;
	struct necp_interface_details interface_details = {};

	if (uap->client_id == 0 || uap->client_id_len != sizeof(u_int32_t) ||
	    uap->buffer_size < sizeof(interface_details) ||
	    uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_interface bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, &interface_index, sizeof(u_int32_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_interface copyin interface_index error (%d)", error);
		goto done;
	}

	if (interface_index == 0) {
		error = ENOENT;
		NECPLOG(LOG_ERR, "necp_client_copy_interface bad interface_index (%d)", interface_index);
		goto done;
	}

	lck_mtx_lock(rnh_lock);
	ifnet_head_lock_shared();
	ifnet_t interface = NULL;
	if (interface_index != IFSCOPE_NONE && interface_index <= (u_int32_t)if_index) {
		interface = ifindex2ifnet[interface_index];
	}

	if (interface != NULL) {
		if (interface->if_xname != NULL) {
			strlcpy((char *)&interface_details.name, interface->if_xname, sizeof(interface_details.name));
		}
		interface_details.index = interface->if_index;
		interface_details.generation = ifnet_get_generation(interface);
		if (interface->if_delegated.ifp != NULL) {
			interface_details.delegate_index = interface->if_delegated.ifp->if_index;
		}
		interface_details.functional_type = if_functional_type(interface, TRUE);
		if (IFNET_IS_EXPENSIVE(interface)) {
			interface_details.flags |= NECP_INTERFACE_FLAG_EXPENSIVE;
		}
		if (IFNET_IS_CONSTRAINED(interface)) {
			interface_details.flags |= NECP_INTERFACE_FLAG_CONSTRAINED;
		}
		if ((interface->if_eflags & IFEF_TXSTART) == IFEF_TXSTART) {
			interface_details.flags |= NECP_INTERFACE_FLAG_TXSTART;
		}
		if ((interface->if_eflags & IFEF_NOACKPRI) == IFEF_NOACKPRI) {
			interface_details.flags |= NECP_INTERFACE_FLAG_NOACKPRI;
		}
		if ((interface->if_eflags & IFEF_3CA) == IFEF_3CA) {
			interface_details.flags |= NECP_INTERFACE_FLAG_3CARRIERAGG;
		}
		if (IFNET_IS_LOW_POWER(interface)) {
			interface_details.flags |= NECP_INTERFACE_FLAG_IS_LOW_POWER;
		}
		if (interface->if_xflags & IFXF_MPK_LOG) {
			interface_details.flags |= NECP_INTERFACE_FLAG_MPK_LOG;
		}
		if (interface->if_flags & IFF_MULTICAST) {
			interface_details.flags |= NECP_INTERFACE_FLAG_SUPPORTS_MULTICAST;
		}
		if (IS_INTF_CLAT46(interface)) {
			interface_details.flags |= NECP_INTERFACE_FLAG_HAS_NAT64;
		}
		interface_details.mtu = interface->if_mtu;

		u_int8_t ipv4_signature_len = sizeof(interface_details.ipv4_signature.signature);
		u_int16_t ipv4_signature_flags;
		if (ifnet_get_netsignature(interface, AF_INET, &ipv4_signature_len, &ipv4_signature_flags,
		    (u_int8_t *)&interface_details.ipv4_signature) != 0) {
			ipv4_signature_len = 0;
		}
		interface_details.ipv4_signature.signature_len = ipv4_signature_len;

		// Check for default scoped routes for IPv4 and IPv6
		union necp_sockaddr_union default_address;
		struct rtentry *v4Route = NULL;
		memset(&default_address, 0, sizeof(default_address));
		default_address.sa.sa_family = AF_INET;
		default_address.sa.sa_len = sizeof(struct sockaddr_in);
		v4Route = rtalloc1_scoped_locked((struct sockaddr *)&default_address, 0, 0,
		    interface->if_index);
		if (v4Route != NULL) {
			if (v4Route->rt_ifp != NULL && !IS_INTF_CLAT46(v4Route->rt_ifp)) {
				interface_details.flags |= NECP_INTERFACE_FLAG_IPV4_ROUTABLE;
			}
			rtfree_locked(v4Route);
			v4Route = NULL;
		}

		struct rtentry *v6Route = NULL;
		memset(&default_address, 0, sizeof(default_address));
		default_address.sa.sa_family = AF_INET6;
		default_address.sa.sa_len = sizeof(struct sockaddr_in6);
		v6Route = rtalloc1_scoped_locked((struct sockaddr *)&default_address, 0, 0,
		    interface->if_index);
		if (v6Route != NULL) {
			if (v6Route->rt_ifp != NULL) {
				interface_details.flags |= NECP_INTERFACE_FLAG_IPV6_ROUTABLE;
			}
			rtfree_locked(v6Route);
			v6Route = NULL;
		}

		u_int8_t ipv6_signature_len = sizeof(interface_details.ipv6_signature.signature);
		u_int16_t ipv6_signature_flags;
		if (ifnet_get_netsignature(interface, AF_INET6, &ipv6_signature_len, &ipv6_signature_flags,
		    (u_int8_t *)&interface_details.ipv6_signature) != 0) {
			ipv6_signature_len = 0;
		}
		interface_details.ipv6_signature.signature_len = ipv6_signature_len;

		ifnet_lock_shared(interface);
		struct ifaddr *ifa = NULL;
		TAILQ_FOREACH(ifa, &interface->if_addrhead, ifa_link) {
			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family == AF_INET) {
				interface_details.flags |= NECP_INTERFACE_FLAG_HAS_NETMASK;
				interface_details.ipv4_netmask = ((struct in_ifaddr *)ifa)->ia_sockmask.sin_addr.s_addr;
				if (interface->if_flags & IFF_BROADCAST) {
					interface_details.flags |= NECP_INTERFACE_FLAG_HAS_BROADCAST;
					interface_details.ipv4_broadcast = ((struct in_ifaddr *)ifa)->ia_broadaddr.sin_addr.s_addr;
				}
			}
			IFA_UNLOCK(ifa);
		}

		interface_details.radio_type = interface->if_radio_type;
		if (interface_details.radio_type == 0 && interface->if_delegated.ifp) {
			interface_details.radio_type = interface->if_delegated.ifp->if_radio_type;
		}
		ifnet_lock_done(interface);
	}

	ifnet_head_done();
	lck_mtx_unlock(rnh_lock);

	// If the client is using an older version of the struct, copy that length
	error = copyout(&interface_details, uap->buffer, sizeof(interface_details));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_interface copyout error (%d)", error);
		goto done;
	}
done:
	*retval = error;

	return error;
}

#if SKYWALK

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_get_interface_address(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	u_int32_t interface_index = IFSCOPE_NONE;
	struct sockaddr_storage address = {};
	const size_t buffer_size = uap->buffer_size;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(u_int32_t) ||
	    buffer_size < sizeof(struct sockaddr_in) ||
	    buffer_size > sizeof(struct sockaddr_storage) ||
	    uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_get_interface_address bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, &interface_index, sizeof(u_int32_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_get_interface_address copyin interface_index error (%d)", error);
		goto done;
	}

	if (interface_index == IFSCOPE_NONE) {
		error = ENOENT;
		NECPLOG(LOG_ERR, "necp_client_get_interface_address bad interface_index (%d)", interface_index);
		goto done;
	}

	error = copyin(uap->buffer, &address, buffer_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_get_interface_address copyin address error (%d)", error);
		goto done;
	}

	if (address.ss_family != AF_INET && address.ss_family != AF_INET6) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_get_interface_address invalid address family (%u)", address.ss_family);
		goto done;
	}

	if (address.ss_len != buffer_size) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_get_interface_address invalid address length (%u)", address.ss_len);
		goto done;
	}

	ifnet_head_lock_shared();
	ifnet_t ifp = NULL;
	if (interface_index != IFSCOPE_NONE && interface_index <= (u_int32_t)if_index) {
		ifp = ifindex2ifnet[interface_index];
	}
	ifnet_head_done();
	if (ifp == NULL) {
		error = ENOENT;
		NECPLOG0(LOG_ERR, "necp_client_get_interface_address no matching interface found");
		goto done;
	}

	struct rtentry *rt = rtalloc1_scoped((struct sockaddr *)&address, 0, 0, interface_index);
	if (rt == NULL) {
		error = EINVAL;
		NECPLOG0(LOG_ERR, "necp_client_get_interface_address route lookup failed");
		goto done;
	}

	uint32_t gencount = 0;
	struct sockaddr_storage local_address = {};
	error = flow_route_select_laddr((union sockaddr_in_4_6 *)&local_address,
	    (union sockaddr_in_4_6 *)&address, ifp, rt, &gencount, 1);
	rtfree(rt);
	rt = NULL;

	if (error) {
		NECPLOG(LOG_ERR, "necp_client_get_interface_address local address selection failed (%d)", error);
		goto done;
	}

	if (local_address.ss_len > buffer_size) {
		error = EMSGSIZE;
		NECPLOG(LOG_ERR, "necp_client_get_interface_address local address too long for buffer (%u)",
		    local_address.ss_len);
		goto done;
	}

	error = copyout(&local_address, uap->buffer, local_address.ss_len);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_get_interface_address copyout error (%d)", error);
		goto done;
	}
done:
	*retval = error;

	return error;
}

extern char *proc_name_address(void *p);

int
necp_stats_ctor(struct skmem_obj_info *oi, struct skmem_obj_info *oim,
    void *arg, uint32_t skmflag)
{
#pragma unused(arg, skmflag)
	struct necp_all_kstats *kstats = SKMEM_OBJ_ADDR(oi);

	ASSERT(oim != NULL && SKMEM_OBJ_ADDR(oim) != NULL);
	ASSERT(SKMEM_OBJ_SIZE(oi) == SKMEM_OBJ_SIZE(oim));

	kstats->necp_stats_ustats = SKMEM_OBJ_ADDR(oim);

	return 0;
}

int
necp_stats_dtor(void *addr, void *arg)
{
#pragma unused(addr, arg)
	struct necp_all_kstats *kstats = addr;

	kstats->necp_stats_ustats = NULL;

	return 0;
}

static void
necp_fd_insert_stats_arena(struct necp_fd_data *fd_data, struct necp_arena_info *nai)
{
	NECP_FD_ASSERT_LOCKED(fd_data);
	VERIFY(!(nai->nai_flags & NAIF_ATTACHED));
	VERIFY(nai->nai_chain.le_next == NULL && nai->nai_chain.le_prev == NULL);

	LIST_INSERT_HEAD(&fd_data->stats_arena_list, nai, nai_chain);
	nai->nai_flags |= NAIF_ATTACHED;
	necp_arena_info_retain(nai);    // for the list
}

static void
necp_fd_remove_stats_arena(struct necp_fd_data *fd_data, struct necp_arena_info *nai)
{
#pragma unused(fd_data)
	NECP_FD_ASSERT_LOCKED(fd_data);
	VERIFY(nai->nai_flags & NAIF_ATTACHED);
	VERIFY(nai->nai_use_count >= 1);

	LIST_REMOVE(nai, nai_chain);
	nai->nai_flags &= ~NAIF_ATTACHED;
	nai->nai_chain.le_next = NULL;
	nai->nai_chain.le_prev = NULL;
	necp_arena_info_release(nai);   // for the list
}

static struct necp_arena_info *
necp_fd_mredirect_stats_arena(struct necp_fd_data *fd_data, struct proc *proc)
{
	struct necp_arena_info *nai, *nai_ret = NULL;

	NECP_FD_ASSERT_LOCKED(fd_data);

	// Redirect currently-active stats arena and remove it from the active state;
	// upon process resumption, new flow request would trigger the creation of
	// another active arena.
	if ((nai = fd_data->stats_arena_active) != NULL) {
		boolean_t need_defunct = FALSE;

		ASSERT(!(nai->nai_flags & (NAIF_REDIRECT | NAIF_DEFUNCT)));
		VERIFY(nai->nai_use_count >= 2);
		ASSERT(nai->nai_arena != NULL);
		ASSERT(nai->nai_mmap.ami_mapref != NULL);

		int err = skmem_arena_mredirect(nai->nai_arena, &nai->nai_mmap, proc, &need_defunct);
		VERIFY(err == 0);
		// must be TRUE since we don't mmap the arena more than once
		VERIFY(need_defunct == TRUE);

		nai->nai_flags |= NAIF_REDIRECT;
		nai_ret = nai;  // return to caller

		necp_arena_info_release(nai);   // for fd_data
		fd_data->stats_arena_active = nai = NULL;
	}

#if (DEVELOPMENT || DEBUG)
	// make sure this list now contains nothing but redirected/defunct arenas
	LIST_FOREACH(nai, &fd_data->stats_arena_list, nai_chain) {
		ASSERT(nai->nai_use_count >= 1);
		ASSERT(nai->nai_flags & (NAIF_REDIRECT | NAIF_DEFUNCT));
	}
#endif /* (DEVELOPMENT || DEBUG) */

	return nai_ret;
}

static void
necp_arena_info_retain(struct necp_arena_info *nai)
{
	nai->nai_use_count++;
	VERIFY(nai->nai_use_count != 0);
}

static void
necp_arena_info_release(struct necp_arena_info *nai)
{
	VERIFY(nai->nai_use_count > 0);
	if (--nai->nai_use_count == 0) {
		necp_arena_info_free(nai);
	}
}

static struct necp_arena_info *
necp_arena_info_alloc(void)
{
	return zalloc_flags(necp_arena_info_zone, Z_WAITOK | Z_ZERO);
}

static void
necp_arena_info_free(struct necp_arena_info *nai)
{
	VERIFY(nai->nai_chain.le_next == NULL && nai->nai_chain.le_prev == NULL);
	VERIFY(nai->nai_use_count == 0);

	// NOTE: destroying the arena requires that all outstanding objects
	// that were allocated have been freed, else it will assert.
	if (nai->nai_arena != NULL) {
		skmem_arena_munmap(nai->nai_arena, &nai->nai_mmap);
		skmem_arena_release(nai->nai_arena);
		OSDecrementAtomic(&necp_arena_count);
		nai->nai_arena = NULL;
		nai->nai_roff = 0;
	}

	ASSERT(nai->nai_arena == NULL);
	ASSERT(nai->nai_mmap.ami_mapref == NULL);
	ASSERT(nai->nai_mmap.ami_arena == NULL);
	ASSERT(nai->nai_mmap.ami_maptask == TASK_NULL);

	zfree(necp_arena_info_zone, nai);
}

static int
necp_arena_create(struct necp_fd_data *fd_data, size_t obj_size, size_t obj_cnt, struct proc *p)
{
	struct skmem_region_params srp_ustats = {};
	struct skmem_region_params srp_kstats = {};
	struct necp_arena_info *nai;
	char name[32];
	int error = 0;

	NECP_FD_ASSERT_LOCKED(fd_data);
	ASSERT(fd_data->stats_arena_active == NULL);
	ASSERT(p != PROC_NULL);
	ASSERT(proc_pid(p) == fd_data->proc_pid);

	// inherit the default parameters for the stats region
	srp_ustats = *skmem_get_default(SKMEM_REGION_USTATS);
	srp_kstats = *skmem_get_default(SKMEM_REGION_KSTATS);

	// enable multi-segment mode
	srp_ustats.srp_cflags &= ~SKMEM_REGION_CR_MONOLITHIC;
	srp_kstats.srp_cflags &= ~SKMEM_REGION_CR_MONOLITHIC;

	// configure and adjust the region parameters
	srp_ustats.srp_r_obj_cnt = srp_kstats.srp_r_obj_cnt = obj_cnt;
	srp_ustats.srp_r_obj_size = srp_kstats.srp_r_obj_size = obj_size;
	skmem_region_params_config(&srp_ustats);
	skmem_region_params_config(&srp_kstats);

	nai = necp_arena_info_alloc();

	nai->nai_proc_pid = fd_data->proc_pid;
	(void) snprintf(name, sizeof(name), "stats-%u.%s.%d", fd_data->stats_arena_gencnt, proc_name_address(p), fd_data->proc_pid);
	nai->nai_arena = skmem_arena_create_for_necp(name, &srp_ustats, &srp_kstats, &error);
	ASSERT(nai->nai_arena != NULL || error != 0);
	if (error != 0) {
		NECPLOG(LOG_ERR, "failed to create stats arena for pid %d\n", fd_data->proc_pid);
	} else {
		OSIncrementAtomic(&necp_arena_count);

		// Get region offsets from base of mmap span; the arena
		// doesn't need to be mmap'd at this point, since we simply
		// compute the relative offset.
		nai->nai_roff = skmem_arena_get_region_offset(nai->nai_arena, SKMEM_REGION_USTATS);

		// map to the task/process; upon success, the base address of the region
		// will be returned in nai_mmap.ami_mapaddr; this can be communicated to
		// the process.
		error = skmem_arena_mmap(nai->nai_arena, p, &nai->nai_mmap);
		if (error != 0) {
			NECPLOG(LOG_ERR, "failed to map stats arena for pid %d\n", fd_data->proc_pid);
		}
	}

	if (error == 0) {
		fd_data->stats_arena_active = nai;
		necp_arena_info_retain(nai);    // for fd_data
		necp_fd_insert_stats_arena(fd_data, nai);
		++fd_data->stats_arena_gencnt;
	} else {
		necp_arena_info_free(nai);
	}

	return error;
}

static int
necp_arena_stats_obj_alloc(struct necp_fd_data *fd_data,
    mach_vm_offset_t *off,
    struct necp_arena_info **stats_arena,
    void **kstats_kaddr,
    boolean_t cansleep)
{
	struct skmem_cache *kstats_cp = NULL;
	void *ustats_obj = NULL;
	void *kstats_obj = NULL;
	struct necp_all_kstats *kstats = NULL;
	struct skmem_obj_info kstats_oi = {};

	ASSERT(off != NULL);
	ASSERT(stats_arena != NULL && *stats_arena == NULL);
	ASSERT(kstats_kaddr != NULL && *kstats_kaddr == NULL);

	NECP_FD_ASSERT_LOCKED(fd_data);
	ASSERT(fd_data->stats_arena_active != NULL);
	ASSERT(fd_data->stats_arena_active->nai_arena != NULL);

	kstats_cp = skmem_arena_necp(fd_data->stats_arena_active->nai_arena)->arc_kstats_cache;
	if ((kstats_obj = skmem_cache_alloc(kstats_cp, (cansleep ? SKMEM_SLEEP : SKMEM_NOSLEEP))) == NULL) {
		return ENOMEM;
	}

	kstats = (struct necp_all_kstats*)kstats_obj;
	ustats_obj = kstats->necp_stats_ustats;

	skmem_cache_get_obj_info(kstats_cp, kstats_obj, &kstats_oi, NULL);
	ASSERT(SKMEM_OBJ_SIZE(&kstats_oi) >= sizeof(struct necp_all_stats));
	// reset all stats counters
	bzero(ustats_obj, SKMEM_OBJ_SIZE(&kstats_oi));
	bzero(&kstats->necp_stats_comm, sizeof(struct necp_all_stats));
	*stats_arena = fd_data->stats_arena_active;
	*kstats_kaddr = kstats_obj;
	// kstats and ustats are mirrored and have the same offset
	*off = fd_data->stats_arena_active->nai_roff + SKMEM_OBJ_ROFF(&kstats_oi);

	return 0;
}

static void
necp_arena_stats_obj_free(struct necp_fd_data *fd_data, struct necp_arena_info *stats_arena, void **kstats_kaddr, mach_vm_address_t *ustats_uaddr)
{
#pragma unused(fd_data)
	NECP_FD_ASSERT_LOCKED(fd_data);

	ASSERT(stats_arena != NULL);
	ASSERT(stats_arena->nai_arena != NULL);
	ASSERT(kstats_kaddr != NULL && *kstats_kaddr != NULL);
	ASSERT(ustats_uaddr != NULL);

	skmem_cache_free(skmem_arena_necp(stats_arena->nai_arena)->arc_kstats_cache, *kstats_kaddr);
	*kstats_kaddr = NULL;
	*ustats_uaddr = 0;
}

// This routine returns the KVA of the sysctls object, as well as the
// offset of that object relative to the mmap base address for the
// task/process.
static void *
necp_arena_sysctls_obj(struct necp_fd_data *fd_data, mach_vm_offset_t *off, size_t *size)
{
	void *objaddr;

	NECP_FD_ASSERT_LOCKED(fd_data);
	ASSERT(fd_data->sysctl_arena != NULL);

	// kernel virtual address of the sysctls object
	objaddr = skmem_arena_system_sysctls_obj_addr(fd_data->sysctl_arena);
	ASSERT(objaddr != NULL);

	// Return the relative offset of the sysctls object; there is
	// only 1 object in the entire sysctls region, and therefore the
	// object's offset is simply the region's offset in the arena.
	// (sysctl_mmap.ami_mapaddr + offset) is the address of this object
	// in the task/process.
	if (off != NULL) {
		*off = fd_data->system_sysctls_roff;
	}

	if (size != NULL) {
		*size = skmem_arena_system_sysctls_obj_size(fd_data->sysctl_arena);
		ASSERT(*size != 0);
	}

	return objaddr;
}

static void
necp_stats_arenas_destroy(struct necp_fd_data *fd_data, boolean_t closing)
{
	struct necp_arena_info *nai, *nai_tmp;

	NECP_FD_ASSERT_LOCKED(fd_data);

	// If reaping (not closing), release reference only for idle active arena; the reference
	// count must be 2 by now, when it's not being referred to by any clients/flows.
	if ((nai = fd_data->stats_arena_active) != NULL && (closing || nai->nai_use_count == 2)) {
		VERIFY(nai->nai_use_count >= 2);
		necp_arena_info_release(nai);   // for fd_data
		fd_data->stats_arena_active = NULL;
	}

	// clean up any defunct arenas left in the list
	LIST_FOREACH_SAFE(nai, &fd_data->stats_arena_list, nai_chain, nai_tmp) {
		// If reaping, release reference if the list holds the last one
		if (closing || nai->nai_use_count == 1) {
			VERIFY(nai->nai_use_count >= 1);
			// callee unchains nai (and may free it)
			necp_fd_remove_stats_arena(fd_data, nai);
		}
	}
}

static void
necp_sysctl_arena_destroy(struct necp_fd_data *fd_data)
{
	NECP_FD_ASSERT_LOCKED(fd_data);

	// NOTE: destroying the arena requires that all outstanding objects
	// that were allocated have been freed, else it will assert.
	if (fd_data->sysctl_arena != NULL) {
		skmem_arena_munmap(fd_data->sysctl_arena, &fd_data->sysctl_mmap);
		skmem_arena_release(fd_data->sysctl_arena);
		OSDecrementAtomic(&necp_sysctl_arena_count);
		fd_data->sysctl_arena = NULL;
		fd_data->system_sysctls_roff = 0;
	}
}

static int
necp_arena_initialize(struct necp_fd_data *fd_data, bool locked)
{
	int error = 0;
	size_t stats_obj_size = MAX(sizeof(struct necp_all_stats), sizeof(struct necp_all_kstats));

	if (!locked) {
		NECP_FD_LOCK(fd_data);
	}
	if (fd_data->stats_arena_active == NULL) {
		error = necp_arena_create(fd_data, stats_obj_size,
		    NECP_MAX_PER_PROCESS_CLIENT_STATISTICS_STRUCTS,
		    current_proc());
	}
	if (!locked) {
		NECP_FD_UNLOCK(fd_data);
	}

	return error;
}

static int
necp_sysctl_arena_initialize(struct necp_fd_data *fd_data, bool locked)
{
	int error = 0;

	if (!locked) {
		NECP_FD_LOCK(fd_data);
	}

	NECP_FD_ASSERT_LOCKED(fd_data);

	if (fd_data->sysctl_arena == NULL) {
		char name[32];
		struct proc *p = current_proc();

		ASSERT(p != PROC_NULL);
		ASSERT(proc_pid(p) == fd_data->proc_pid);

		(void) snprintf(name, sizeof(name), "sysctl.%s.%d", proc_name_address(p), fd_data->proc_pid);
		fd_data->sysctl_arena = skmem_arena_create_for_system(name, &error);
		ASSERT(fd_data->sysctl_arena != NULL || error != 0);
		if (error != 0) {
			NECPLOG(LOG_ERR, "failed to create arena for pid %d\n", fd_data->proc_pid);
		} else {
			OSIncrementAtomic(&necp_sysctl_arena_count);

			// Get region offsets from base of mmap span; the arena
			// doesn't need to be mmap'd at this point, since we simply
			// compute the relative offset.
			fd_data->system_sysctls_roff = skmem_arena_get_region_offset(fd_data->sysctl_arena, SKMEM_REGION_SYSCTLS);

			// map to the task/process; upon success, the base address of the region
			// will be returned in nai_mmap.ami_mapaddr; this can be communicated to
			// the process.
			error = skmem_arena_mmap(fd_data->sysctl_arena, p, &fd_data->sysctl_mmap);
			if (error != 0) {
				NECPLOG(LOG_ERR, "failed to map sysctl arena for pid %d\n", fd_data->proc_pid);
				necp_sysctl_arena_destroy(fd_data);
			}
		}
	}

	if (!locked) {
		NECP_FD_UNLOCK(fd_data);
	}

	return error;
}

static int
necp_client_stats_bufreq(struct necp_fd_data *fd_data,
    struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    struct necp_stats_bufreq *bufreq,
    struct necp_stats_hdr *out_header)
{
	int error = 0;
	NECP_CLIENT_ASSERT_LOCKED(client);
	NECP_FD_ASSERT_LOCKED(fd_data);

	if ((bufreq->necp_stats_bufreq_id == NECP_CLIENT_STATISTICS_BUFREQ_ID) &&
	    ((bufreq->necp_stats_bufreq_type == NECP_CLIENT_STATISTICS_TYPE_TCP &&
	    bufreq->necp_stats_bufreq_ver == NECP_CLIENT_STATISTICS_TYPE_TCP_CURRENT_VER) ||
	    (bufreq->necp_stats_bufreq_type == NECP_CLIENT_STATISTICS_TYPE_UDP &&
	    bufreq->necp_stats_bufreq_ver == NECP_CLIENT_STATISTICS_TYPE_UDP_CURRENT_VER) ||
	    (bufreq->necp_stats_bufreq_type == NECP_CLIENT_STATISTICS_TYPE_QUIC &&
	    bufreq->necp_stats_bufreq_ver == NECP_CLIENT_STATISTICS_TYPE_QUIC_CURRENT_VER)) &&
	    (bufreq->necp_stats_bufreq_size == sizeof(struct necp_all_stats))) {
		// There should be one and only one stats allocation per client.
		// If asked more than once, we just repeat ourselves.
		if (flow_registration->ustats_uaddr == 0) {
			mach_vm_offset_t off;
			ASSERT(flow_registration->stats_arena == NULL);
			ASSERT(flow_registration->kstats_kaddr == NULL);
			ASSERT(flow_registration->ustats_uaddr == 0);
			error = necp_arena_stats_obj_alloc(fd_data, &off, &flow_registration->stats_arena, &flow_registration->kstats_kaddr, FALSE);
			if (error == 0) {
				// upon success, hold a reference for the client; this is released when the client is removed/closed
				ASSERT(flow_registration->stats_arena != NULL);
				necp_arena_info_retain(flow_registration->stats_arena);

				// compute user address based on mapping info and object offset
				flow_registration->ustats_uaddr = flow_registration->stats_arena->nai_mmap.ami_mapaddr + off;

				// add to collect_stats list
				NECP_STATS_LIST_LOCK_EXCLUSIVE();
				necp_client_retain_locked(client); // Add a reference to the client
				LIST_INSERT_HEAD(&necp_collect_stats_flow_list, flow_registration, collect_stats_chain);
				NECP_STATS_LIST_UNLOCK();
				necp_schedule_collect_stats_clients(FALSE);
			} else {
				ASSERT(flow_registration->stats_arena == NULL);
				ASSERT(flow_registration->kstats_kaddr == NULL);
			}
		}
		if (flow_registration->ustats_uaddr != 0) {
			ASSERT(error == 0);
			ASSERT(flow_registration->stats_arena != NULL);
			ASSERT(flow_registration->kstats_kaddr != NULL);

			struct necp_all_kstats *kstats = (struct necp_all_kstats *)flow_registration->kstats_kaddr;
			kstats->necp_stats_ustats->all_stats_u.tcp_stats.necp_tcp_hdr.necp_stats_type = bufreq->necp_stats_bufreq_type;
			kstats->necp_stats_ustats->all_stats_u.tcp_stats.necp_tcp_hdr.necp_stats_ver = bufreq->necp_stats_bufreq_ver;

			if (out_header) {
				out_header->necp_stats_type = bufreq->necp_stats_bufreq_type;
				out_header->necp_stats_ver = bufreq->necp_stats_bufreq_ver;
			}

			bufreq->necp_stats_bufreq_uaddr = flow_registration->ustats_uaddr;
		}
	} else {
		error = EINVAL;
	}

	return error;
}

static int
necp_client_stats_initial(struct necp_client_flow_registration *flow_registration, uint32_t stats_type, uint32_t stats_ver)
{
	// An attempted create
	assert(flow_registration->stats_handler_context == NULL);
	assert(flow_registration->stats_arena);
	assert(flow_registration->ustats_uaddr);
	assert(flow_registration->kstats_kaddr);

	int error = 0;

	switch (stats_type) {
	case NECP_CLIENT_STATISTICS_TYPE_TCP: {
		if (stats_ver == NECP_CLIENT_STATISTICS_TYPE_TCP_VER_1) {
			flow_registration->stats_handler_context = ntstat_userland_stats_open((userland_stats_provider_context *)flow_registration,
			    NSTAT_PROVIDER_TCP_USERLAND, 0, necp_request_tcp_netstats, necp_find_extension_info);
			if (flow_registration->stats_handler_context == NULL) {
				error = EIO;
			}
		} else {
			error = ENOTSUP;
		}
		break;
	}
	case NECP_CLIENT_STATISTICS_TYPE_UDP: {
		if (stats_ver == NECP_CLIENT_STATISTICS_TYPE_UDP_VER_1) {
			flow_registration->stats_handler_context = ntstat_userland_stats_open((userland_stats_provider_context *)flow_registration,
			    NSTAT_PROVIDER_UDP_USERLAND, 0, necp_request_udp_netstats, necp_find_extension_info);
			if (flow_registration->stats_handler_context == NULL) {
				error = EIO;
			}
		} else {
			error = ENOTSUP;
		}
		break;
	}
	case NECP_CLIENT_STATISTICS_TYPE_QUIC: {
		if (stats_ver == NECP_CLIENT_STATISTICS_TYPE_QUIC_VER_1 && flow_registration->flags & NECP_CLIENT_FLOW_FLAGS_ALLOW_NEXUS) {
			flow_registration->stats_handler_context = ntstat_userland_stats_open((userland_stats_provider_context *)flow_registration,
			    NSTAT_PROVIDER_QUIC_USERLAND, 0, necp_request_quic_netstats, necp_find_extension_info);
			if (flow_registration->stats_handler_context == NULL) {
				error = EIO;
			}
		} else {
			error = ENOTSUP;
		}
		break;
	}
	default: {
		error = ENOTSUP;
		break;
	}
	}
	return error;
}

static int
necp_stats_initialize(struct necp_fd_data *fd_data,
    struct necp_client *client,
    struct necp_client_flow_registration *flow_registration,
    struct necp_stats_bufreq *bufreq)
{
	int error = 0;
	struct necp_stats_hdr stats_hdr = {};

	NECP_CLIENT_ASSERT_LOCKED(client);
	NECP_FD_ASSERT_LOCKED(fd_data);
	VERIFY(fd_data->stats_arena_active != NULL);
	VERIFY(fd_data->stats_arena_active->nai_arena != NULL);
	VERIFY(!(fd_data->stats_arena_active->nai_flags & (NAIF_REDIRECT | NAIF_DEFUNCT)));

	if (bufreq == NULL) {
		return EINVAL;
	}

	// Setup stats region
	error = necp_client_stats_bufreq(fd_data, client, flow_registration, bufreq, &stats_hdr);
	if (error) {
		return error;
	}
	// Notify ntstat about new flow
	if (flow_registration->stats_handler_context == NULL) {
		error = necp_client_stats_initial(flow_registration, stats_hdr.necp_stats_type, stats_hdr.necp_stats_ver);
		if (flow_registration->stats_handler_context != NULL) {
			ntstat_userland_stats_event(flow_registration->stats_handler_context, NECP_CLIENT_STATISTICS_EVENT_INIT);
		}
		NECP_CLIENT_FLOW_LOG(client, flow_registration, "Initialized stats <error %d>", error);
	}

	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_map_sysctls(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int result = 0;
	if (!retval) {
		retval = &result;
	}

	do {
		mach_vm_address_t uaddr = 0;
		if (uap->buffer_size != sizeof(uaddr)) {
			*retval = EINVAL;
			break;
		}

		*retval = necp_sysctl_arena_initialize(fd_data, false);
		if (*retval != 0) {
			break;
		}

		mach_vm_offset_t off = 0;
		void *location = NULL;
		NECP_FD_LOCK(fd_data);
		location = necp_arena_sysctls_obj(fd_data, &off, NULL);
		NECP_FD_UNLOCK(fd_data);

		if (location == NULL) {
			*retval = ENOENT;
			break;
		}

		uaddr = fd_data->sysctl_mmap.ami_mapaddr + off;
		*retval = copyout(&uaddr, uap->buffer, sizeof(uaddr));
	} while (false);

	return *retval;
}

#endif /* !SKYWALK */

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_copy_route_statistics(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t) ||
	    uap->buffer_size < sizeof(struct necp_stat_counts) || uap->buffer == 0) {
		NECPLOG0(LOG_ERR, "necp_client_copy_route_statistics bad input");
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_copy_route_statistics copyin client_id error (%d)", error);
		goto done;
	}

	// Lock
	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client != NULL) {
		NECP_CLIENT_ROUTE_LOCK(client);
		struct necp_stat_counts route_stats = {};
		if (client->current_route != NULL && client->current_route->rt_stats != NULL) {
			struct nstat_counts     *rt_stats = client->current_route->rt_stats;
			atomic_get_64(route_stats.necp_stat_rxpackets, &rt_stats->nstat_rxpackets);
			atomic_get_64(route_stats.necp_stat_rxbytes, &rt_stats->nstat_rxbytes);
			atomic_get_64(route_stats.necp_stat_txpackets, &rt_stats->nstat_txpackets);
			atomic_get_64(route_stats.necp_stat_txbytes, &rt_stats->nstat_txbytes);
			route_stats.necp_stat_rxduplicatebytes = rt_stats->nstat_rxduplicatebytes;
			route_stats.necp_stat_rxoutoforderbytes = rt_stats->nstat_rxoutoforderbytes;
			route_stats.necp_stat_txretransmit = rt_stats->nstat_txretransmit;
			route_stats.necp_stat_connectattempts = rt_stats->nstat_connectattempts;
			route_stats.necp_stat_connectsuccesses = rt_stats->nstat_connectsuccesses;
			route_stats.necp_stat_min_rtt = rt_stats->nstat_min_rtt;
			route_stats.necp_stat_avg_rtt = rt_stats->nstat_avg_rtt;
			route_stats.necp_stat_var_rtt = rt_stats->nstat_var_rtt;
			route_stats.necp_stat_route_flags = client->current_route->rt_flags;
		}

		// Unlock before copying out
		NECP_CLIENT_ROUTE_UNLOCK(client);
		NECP_CLIENT_UNLOCK(client);
		NECP_FD_UNLOCK(fd_data);

		error = copyout(&route_stats, uap->buffer, sizeof(route_stats));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_copy_route_statistics copyout error (%d)", error);
		}
	} else {
		// Unlock
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
	}


done:
	*retval = error;
	return error;
}

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_update_cache(struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	struct necp_client *client = NULL;
	uuid_t client_id;

	if (uap->client_id == 0 || uap->client_id_len != sizeof(uuid_t)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, client_id, sizeof(uuid_t));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_update_cache copyin client_id error (%d)", error);
		goto done;
	}

	NECP_FD_LOCK(fd_data);
	client = necp_client_fd_find_client_and_lock(fd_data, client_id);
	if (client == NULL) {
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
		goto done;
	}

	struct necp_client_flow_registration *flow_registration = necp_client_find_flow(client, client_id);
	if (flow_registration == NULL) {
		NECP_CLIENT_UNLOCK(client);
		NECP_FD_UNLOCK(fd_data);
		error = ENOENT;
		goto done;
	}

	NECP_CLIENT_ROUTE_LOCK(client);
	// This needs to be changed when TFO/ECN is supported by multiple flows
	struct necp_client_flow *flow = LIST_FIRST(&flow_registration->flow_list);
	if (flow == NULL ||
	    (flow->remote_addr.sa.sa_family != AF_INET &&
	    flow->remote_addr.sa.sa_family != AF_INET6) ||
	    (flow->local_addr.sa.sa_family != AF_INET &&
	    flow->local_addr.sa.sa_family != AF_INET6)) {
		error = EINVAL;
		NECPLOG(LOG_ERR, "necp_client_update_cache no flow error (%d)", error);
		goto done_unlock;
	}

	necp_cache_buffer cache_buffer;
	memset(&cache_buffer, 0, sizeof(cache_buffer));

	if (uap->buffer_size != sizeof(necp_cache_buffer) ||
	    uap->buffer == USER_ADDR_NULL) {
		error = EINVAL;
		goto done_unlock;
	}

	error = copyin(uap->buffer, &cache_buffer, sizeof(cache_buffer));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_update_cache copyin cache buffer error (%d)", error);
		goto done_unlock;
	}

	if (cache_buffer.necp_cache_buf_type == NECP_CLIENT_CACHE_TYPE_ECN &&
	    cache_buffer.necp_cache_buf_ver == NECP_CLIENT_CACHE_TYPE_ECN_VER_1) {
		if (cache_buffer.necp_cache_buf_size != sizeof(necp_tcp_ecn_cache) ||
		    cache_buffer.necp_cache_buf_addr == USER_ADDR_NULL) {
			error = EINVAL;
			goto done_unlock;
		}

		necp_tcp_ecn_cache ecn_cache_buffer;
		memset(&ecn_cache_buffer, 0, sizeof(ecn_cache_buffer));

		error = copyin(cache_buffer.necp_cache_buf_addr, &ecn_cache_buffer, sizeof(necp_tcp_ecn_cache));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_update_cache copyin ecn cache buffer error (%d)", error);
			goto done_unlock;
		}

		if (client->current_route != NULL && client->current_route->rt_ifp != NULL) {
			if (!client->platform_binary) {
				ecn_cache_buffer.necp_tcp_ecn_heuristics_success = 0;
			}
			tcp_heuristics_ecn_update(&ecn_cache_buffer, client->current_route->rt_ifp,
			    (union sockaddr_in_4_6 *)&flow->local_addr);
		}
	} else if (cache_buffer.necp_cache_buf_type == NECP_CLIENT_CACHE_TYPE_TFO &&
	    cache_buffer.necp_cache_buf_ver == NECP_CLIENT_CACHE_TYPE_TFO_VER_1) {
		if (cache_buffer.necp_cache_buf_size != sizeof(necp_tcp_tfo_cache) ||
		    cache_buffer.necp_cache_buf_addr == USER_ADDR_NULL) {
			error = EINVAL;
			goto done_unlock;
		}

		necp_tcp_tfo_cache tfo_cache_buffer;
		memset(&tfo_cache_buffer, 0, sizeof(tfo_cache_buffer));

		error = copyin(cache_buffer.necp_cache_buf_addr, &tfo_cache_buffer, sizeof(necp_tcp_tfo_cache));
		if (error) {
			NECPLOG(LOG_ERR, "necp_client_update_cache copyin tfo cache buffer error (%d)", error);
			goto done_unlock;
		}

		if (client->current_route != NULL && client->current_route->rt_ifp != NULL) {
			if (!client->platform_binary) {
				tfo_cache_buffer.necp_tcp_tfo_heuristics_success = 0;
			}
			tcp_heuristics_tfo_update(&tfo_cache_buffer, client->current_route->rt_ifp,
			    (union sockaddr_in_4_6 *)&flow->local_addr,
			    (union sockaddr_in_4_6 *)&flow->remote_addr);
		}
	} else {
		error = EINVAL;
	}
done_unlock:
	NECP_CLIENT_ROUTE_UNLOCK(client);
	NECP_CLIENT_UNLOCK(client);
	NECP_FD_UNLOCK(fd_data);
done:
	*retval = error;
	return error;
}

#define NECP_CLIENT_ACTION_SIGN_DEFAULT_HOSTNAME_LENGTH 64
#define NECP_CLIENT_ACTION_SIGN_MAX_HOSTNAME_LENGTH 1024

#define NECP_CLIENT_ACTION_SIGN_TAG_LENGTH 32

static NECP_CLIENT_ACTION_FUNCTION int
necp_client_sign(__unused struct necp_fd_data *fd_data, struct necp_client_action_args *uap, int *retval)
{
	int error = 0;
	u_int32_t hostname_length = 0;
	u_int8_t tag[NECP_CLIENT_ACTION_SIGN_TAG_LENGTH] = {};
	struct necp_client_signable signable = {};
	union necp_sockaddr_union address_answer = {};
	u_int8_t *client_hostname = NULL;
	u_int8_t *allocated_hostname = NULL;
	u_int8_t default_hostname[NECP_CLIENT_ACTION_SIGN_DEFAULT_HOSTNAME_LENGTH] = "";
	uint32_t tag_size = sizeof(tag);

	*retval = 0;

	const bool has_resolver_entitlement = (priv_check_cred(kauth_cred_get(), PRIV_NET_VALIDATED_RESOLVER, 0) == 0);
	if (!has_resolver_entitlement) {
		NECPLOG0(LOG_ERR, "Process does not hold the necessary entitlement to sign resolver answers");
		error = EPERM;
		goto done;
	}

	if (uap->client_id == 0 || uap->client_id_len < sizeof(struct necp_client_signable)) {
		error = EINVAL;
		goto done;
	}

	if (uap->buffer == 0 || uap->buffer_size != NECP_CLIENT_ACTION_SIGN_TAG_LENGTH) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id, &signable, sizeof(signable));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_sign copyin signable error (%d)", error);
		goto done;
	}

	if (signable.sign_type != NECP_CLIENT_SIGN_TYPE_RESOLVER_ANSWER) {
		NECPLOG(LOG_ERR, "necp_client_sign unknown signable type (%u)", signable.sign_type);
		error = EINVAL;
		goto done;
	}

	if (uap->client_id_len < sizeof(struct necp_client_resolver_answer)) {
		error = EINVAL;
		goto done;
	}

	error = copyin(uap->client_id + sizeof(signable), &address_answer, sizeof(address_answer));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_sign copyin address_answer error (%d)", error);
		goto done;
	}

	error = copyin(uap->client_id + sizeof(signable) + sizeof(address_answer), &hostname_length, sizeof(hostname_length));
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_sign copyin hostname_length error (%d)", error);
		goto done;
	}

	if (hostname_length > NECP_CLIENT_ACTION_SIGN_MAX_HOSTNAME_LENGTH) {
		error = EINVAL;
		goto done;
	}

	if (hostname_length > NECP_CLIENT_ACTION_SIGN_DEFAULT_HOSTNAME_LENGTH) {
		if ((allocated_hostname = (u_int8_t *)kalloc_data(hostname_length, Z_WAITOK | Z_ZERO)) == NULL) {
			NECPLOG(LOG_ERR, "necp_client_sign malloc hostname %u failed", hostname_length);
			error = ENOMEM;
			goto done;
		}

		client_hostname = allocated_hostname;
	} else {
		client_hostname = default_hostname;
	}

	error = copyin(uap->client_id + sizeof(signable) + sizeof(address_answer) + sizeof(hostname_length), client_hostname, hostname_length);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_sign copyin hostname error (%d)", error);
		goto done;
	}

	address_answer.sin.sin_port = 0;
	error = necp_sign_resolver_answer(signable.client_id, client_hostname, hostname_length,
	    (u_int8_t *)&address_answer, sizeof(address_answer),
	    tag, &tag_size);
	if (tag_size != sizeof(tag)) {
		NECPLOG(LOG_ERR, "necp_client_sign unexpected tag size %u", tag_size);
		error = EINVAL;
		goto done;
	}
	error = copyout(tag, uap->buffer, tag_size);
	if (error) {
		NECPLOG(LOG_ERR, "necp_client_sign copyout error (%d)", error);
		goto done;
	}

done:
	if (allocated_hostname != NULL) {
		kfree_data(allocated_hostname, hostname_length);
		allocated_hostname = NULL;
	}
	*retval = error;
	return error;
}

int
necp_client_action(struct proc *p, struct necp_client_action_args *uap, int *retval)
{
	struct fileproc *fp;
	int error = 0;
	int return_value = 0;
	struct necp_fd_data *fd_data = NULL;

	error = necp_find_fd_data(p, uap->necp_fd, &fp, &fd_data);
	if (error != 0) {
		NECPLOG(LOG_ERR, "necp_client_action find fd error (%d)", error);
		return error;
	}

	u_int32_t action = uap->action;

#if CONFIG_MACF
	error = mac_necp_check_client_action(p, fp->fp_glob, action);
	if (error) {
		return_value = error;
		goto done;
	}
#endif /* MACF */

	switch (action) {
	case NECP_CLIENT_ACTION_ADD: {
		return_value = necp_client_add(p, fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_CLAIM: {
		return_value = necp_client_claim(p, fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_REMOVE: {
		return_value = necp_client_remove(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_PARAMETERS:
	case NECP_CLIENT_ACTION_COPY_RESULT:
	case NECP_CLIENT_ACTION_COPY_UPDATED_RESULT: {
		return_value = necp_client_copy(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_LIST: {
		return_value = necp_client_list(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_ADD_FLOW: {
		return_value = necp_client_add_flow(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_REMOVE_FLOW: {
		return_value = necp_client_remove_flow(fd_data, uap, retval);
		break;
	}
#if SKYWALK
	case NECP_CLIENT_ACTION_REQUEST_NEXUS_INSTANCE: {
		return_value = necp_client_request_nexus(fd_data, uap, retval);
		break;
	}
#endif /* !SKYWALK */
	case NECP_CLIENT_ACTION_AGENT: {
		return_value = necp_client_agent_action(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_AGENT: {
		return_value = necp_client_copy_agent(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_AGENT_USE: {
		return_value = necp_client_agent_use(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_ACQUIRE_AGENT_TOKEN: {
		return_value = necp_client_acquire_agent_token(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_INTERFACE: {
		return_value = necp_client_copy_interface(fd_data, uap, retval);
		break;
	}
#if SKYWALK
	case NECP_CLIENT_ACTION_GET_INTERFACE_ADDRESS: {
		return_value = necp_client_get_interface_address(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_SET_STATISTICS: {
		return_value = ENOTSUP;
		break;
	}
	case NECP_CLIENT_ACTION_MAP_SYSCTLS: {
		return_value = necp_client_map_sysctls(fd_data, uap, retval);
		break;
	}
#endif /* !SKYWALK */
	case NECP_CLIENT_ACTION_COPY_ROUTE_STATISTICS: {
		return_value = necp_client_copy_route_statistics(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_UPDATE_CACHE: {
		return_value = necp_client_update_cache(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_COPY_CLIENT_UPDATE: {
		return_value = necp_client_copy_client_update(fd_data, uap, retval);
		break;
	}
	case NECP_CLIENT_ACTION_SIGN: {
		return_value = necp_client_sign(fd_data, uap, retval);
		break;
	}
	default: {
		NECPLOG(LOG_ERR, "necp_client_action unknown action (%u)", action);
		return_value = EINVAL;
		break;
	}
	}

done:
	fp_drop(p, uap->necp_fd, fp, 0);
	return return_value;
}

#define NECP_MAX_MATCH_POLICY_PARAMETER_SIZE 1024

int
necp_match_policy(struct proc *p, struct necp_match_policy_args *uap, int32_t *retval)
{
#pragma unused(retval)
	u_int8_t *parameters = NULL;
	struct necp_aggregate_result returned_result;
	int error = 0;

	if (uap == NULL) {
		error = EINVAL;
		goto done;
	}

	if (uap->parameters == 0 || uap->parameters_size == 0 || uap->parameters_size > NECP_MAX_MATCH_POLICY_PARAMETER_SIZE || uap->returned_result == 0) {
		error = EINVAL;
		goto done;
	}

	parameters = (u_int8_t *)kalloc_data(uap->parameters_size, Z_WAITOK | Z_ZERO);
	if (parameters == NULL) {
		error = ENOMEM;
		goto done;
	}
	// Copy parameters in
	error = copyin(uap->parameters, parameters, uap->parameters_size);
	if (error) {
		goto done;
	}

	error = necp_application_find_policy_match_internal(p, parameters, uap->parameters_size,
	    &returned_result, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, false, false, NULL);
	if (error) {
		goto done;
	}

	// Copy return value back
	error = copyout(&returned_result, uap->returned_result, sizeof(struct necp_aggregate_result));
	if (error) {
		goto done;
	}
done:
	if (parameters != NULL) {
		kfree_data(parameters, uap->parameters_size);
	}
	return error;
}

/// Socket operations

static errno_t
necp_set_socket_attribute(u_int8_t *buffer, size_t buffer_length, u_int8_t type, char **buffer_p, bool *single_tlv)
{
	int error = 0;
	int cursor = 0;
	size_t string_size = 0;
	char *local_string = NULL;
	u_int8_t *value = NULL;

	cursor = necp_buffer_find_tlv(buffer, buffer_length, 0, type, NULL, 0);
	if (cursor < 0) {
		// This will clear out the parameter
		goto done;
	}

	string_size = necp_buffer_get_tlv_length(buffer, cursor);
	if (single_tlv != NULL && (buffer_length == sizeof(struct necp_tlv_header) + string_size)) {
		*single_tlv = true;
	}
	if (string_size == 0 || string_size > NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) {
		// This will clear out the parameter
		goto done;
	}

	local_string = (char *)kalloc_data(string_size + 1, Z_WAITOK | Z_ZERO);
	if (local_string == NULL) {
		NECPLOG(LOG_ERR, "Failed to allocate a socket attribute buffer (size %zu)", string_size);
		goto fail;
	}

	value = necp_buffer_get_tlv_value(buffer, cursor, NULL);
	if (value == NULL) {
		NECPLOG0(LOG_ERR, "Failed to get socket attribute");
		goto fail;
	}

	memcpy(local_string, value, string_size);
	local_string[string_size] = 0;

done:
	if (*buffer_p != NULL) {
		kfree_data_addr(*buffer_p);
		*buffer_p = NULL;
	}

	*buffer_p = local_string;
	return 0;
fail:
	if (local_string != NULL) {
		kfree_data(local_string, string_size + 1);
	}
	return error;
}

errno_t
necp_set_socket_attributes(struct inp_necp_attributes *attributes, struct sockopt *sopt)
{
	int error = 0;
	u_int8_t *buffer = NULL;
	bool single_tlv = false;
	size_t valsize = sopt->sopt_valsize;
	if (valsize == 0 ||
	    valsize > ((sizeof(struct necp_tlv_header) + NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) * 4)) {
		goto done;
	}

	buffer = (u_int8_t *)kalloc_data(valsize, Z_WAITOK | Z_ZERO);
	if (buffer == NULL) {
		goto done;
	}

	error = sooptcopyin(sopt, buffer, valsize, 0);
	if (error) {
		goto done;
	}

	// If NECP_TLV_ATTRIBUTE_DOMAIN_CONTEXT is being set/cleared separately from the other attributes,
	// do not clear other attributes.
	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_DOMAIN_CONTEXT, &attributes->inp_domain_context, &single_tlv);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set domain context TLV for socket attributes");
		goto done;
	}
	if (single_tlv == true) {
		goto done;
	}

	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_DOMAIN, &attributes->inp_domain, NULL);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set domain TLV for socket attributes");
		goto done;
	}

	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_DOMAIN_OWNER, &attributes->inp_domain_owner, NULL);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set domain owner TLV for socket attributes");
		goto done;
	}

	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_TRACKER_DOMAIN, &attributes->inp_tracker_domain, NULL);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set tracker domain TLV for socket attributes");
		goto done;
	}

	error = necp_set_socket_attribute(buffer, valsize, NECP_TLV_ATTRIBUTE_ACCOUNT, &attributes->inp_account, NULL);
	if (error) {
		NECPLOG0(LOG_ERR, "Could not set account TLV for socket attributes");
		goto done;
	}

done:
	NECP_SOCKET_ATTRIBUTE_LOG("NECP ATTRIBUTES SOCKET - domain <%s> owner <%s> context <%s> tracker domain <%s> account <%s>",
	    attributes->inp_domain,
	    attributes->inp_domain_owner,
	    attributes->inp_domain_context,
	    attributes->inp_tracker_domain,
	    attributes->inp_account);

	if (necp_debug) {
		NECPLOG(LOG_DEBUG, "Set on socket: Domain %s, Domain owner %s, Domain context %s, Tracker domain %s, Account %s",
		    attributes->inp_domain,
		    attributes->inp_domain_owner,
		    attributes->inp_domain_context,
		    attributes->inp_tracker_domain,
		    attributes->inp_account);
	}

	if (buffer != NULL) {
		kfree_data(buffer, valsize);
	}

	return error;
}

errno_t
necp_get_socket_attributes(struct inp_necp_attributes *attributes, struct sockopt *sopt)
{
	int error = 0;
	u_int8_t *buffer = NULL;
	u_int8_t *cursor = NULL;
	size_t valsize = 0;

	if (attributes->inp_domain != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(attributes->inp_domain);
	}
	if (attributes->inp_domain_owner != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(attributes->inp_domain_owner);
	}
	if (attributes->inp_domain_context != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(attributes->inp_domain_context);
	}
	if (attributes->inp_tracker_domain != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(attributes->inp_tracker_domain);
	}
	if (attributes->inp_account != NULL) {
		valsize += sizeof(struct necp_tlv_header) + strlen(attributes->inp_account);
	}
	if (valsize == 0) {
		goto done;
	}

	buffer = (u_int8_t *)kalloc_data(valsize, Z_WAITOK | Z_ZERO);
	if (buffer == NULL) {
		goto done;
	}

	cursor = buffer;
	if (attributes->inp_domain != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_DOMAIN, strlen(attributes->inp_domain), attributes->inp_domain,
		    buffer, valsize);
	}

	if (attributes->inp_domain_owner != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_DOMAIN_OWNER, strlen(attributes->inp_domain_owner), attributes->inp_domain_owner,
		    buffer, valsize);
	}

	if (attributes->inp_domain_context != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_DOMAIN_CONTEXT, strlen(attributes->inp_domain_context), attributes->inp_domain_context,
		    buffer, valsize);
	}

	if (attributes->inp_tracker_domain != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_TRACKER_DOMAIN, strlen(attributes->inp_tracker_domain), attributes->inp_tracker_domain,
		    buffer, valsize);
	}

	if (attributes->inp_account != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_TLV_ATTRIBUTE_ACCOUNT, strlen(attributes->inp_account), attributes->inp_account,
		    buffer, valsize);
	}

	error = sooptcopyout(sopt, buffer, valsize);
	if (error) {
		goto done;
	}
done:
	if (buffer != NULL) {
		kfree_data(buffer, valsize);
	}

	return error;
}

/*
 * necp_set_socket_domain_attributes
 * Called from soconnectlock/soconnectxlock to directly set the tracker domain and owner for
 * a newly marked tracker socket.
 */
errno_t
necp_set_socket_domain_attributes(struct socket *so, const char *domain, const char *domain_owner)
{
	int error = 0;
	struct inpcb *inp = NULL;
	u_int8_t *buffer = NULL;
	size_t valsize = 0;

	if (SOCK_DOM(so) != PF_INET && SOCK_DOM(so) != PF_INET6) {
		error = EINVAL;
		goto fail;
	}

	// Set domain (required)

	valsize = strlen(domain);
	if (valsize == 0 || valsize > NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) {
		error = EINVAL;
		goto fail;
	}

	buffer = (u_int8_t *)kalloc_data(valsize + 1, Z_WAITOK | Z_ZERO);
	if (buffer == NULL) {
		error = ENOMEM;
		goto fail;
	}
	bcopy(domain, buffer, valsize);
	buffer[valsize] = 0;

	inp = sotoinpcb(so);
	// Do not overwrite a previously set domain if tracker domain is different.
	if (inp->inp_necp_attributes.inp_domain != NULL) {
		if (strlen(inp->inp_necp_attributes.inp_domain) != strlen(domain) ||
		    strncmp(inp->inp_necp_attributes.inp_domain, domain, strlen(domain)) != 0) {
			if (inp->inp_necp_attributes.inp_tracker_domain != NULL) {
				kfree_data_addr(inp->inp_necp_attributes.inp_tracker_domain);
				inp->inp_necp_attributes.inp_tracker_domain = NULL;
			}
			inp->inp_necp_attributes.inp_tracker_domain = (char *)buffer;
		}
	} else {
		inp->inp_necp_attributes.inp_domain = (char *)buffer;
	}
	buffer = NULL;

	// set domain_owner (required only for tracker)
	if (!(so->so_flags1 & SOF1_KNOWN_TRACKER)) {
		goto done;
	}

	valsize = strlen(domain_owner);
	if (valsize == 0 || valsize > NECP_MAX_SOCKET_ATTRIBUTE_STRING_LENGTH) {
		error = EINVAL;
		goto fail;
	}

	buffer = (u_int8_t *)kalloc_data(valsize + 1, Z_WAITOK | Z_ZERO);
	if (buffer == NULL) {
		error = ENOMEM;
		goto fail;
	}
	bcopy(domain_owner, buffer, valsize);
	buffer[valsize] = 0;

	inp = sotoinpcb(so);
	if (inp->inp_necp_attributes.inp_domain_owner != NULL) {
		kfree_data_addr(inp->inp_necp_attributes.inp_domain_owner);
		inp->inp_necp_attributes.inp_domain_owner = NULL;
	}
	inp->inp_necp_attributes.inp_domain_owner = (char *)buffer;
	buffer = NULL;

done:
	// Log if it is a known tracker
	if (so->so_flags1 & SOF1_KNOWN_TRACKER) {
		NECP_CLIENT_TRACKER_LOG(NECP_SOCKET_PID(so),
		    "NECP ATTRIBUTES SOCKET - domain <%s> owner <%s> context <%s> tracker domain <%s> account <%s> "
		    "<so flags - is_tracker %X non-app-initiated %X app-approved-domain %X",
		    inp->inp_necp_attributes.inp_domain ? "present" : "not set",
		    inp->inp_necp_attributes.inp_domain_owner ? "present" : "not set",
		    inp->inp_necp_attributes.inp_domain_context ? "present" : "not set",
		    inp->inp_necp_attributes.inp_tracker_domain ? "present" : "not set",
		    inp->inp_necp_attributes.inp_account ? "present" : "not set",
		    so->so_flags1 & SOF1_KNOWN_TRACKER,
		    so->so_flags1 & SOF1_TRACKER_NON_APP_INITIATED,
		    so->so_flags1 & SOF1_APPROVED_APP_DOMAIN);
	}

	NECP_SOCKET_PARAMS_LOG(so, "NECP ATTRIBUTES SOCKET - domain <%s> owner <%s> context <%s> tracker domain <%s> account <%s> "
	    "<so flags - is_tracker %X non-app-initiated %X app-approved-domain %X",
	    inp->inp_necp_attributes.inp_domain,
	    inp->inp_necp_attributes.inp_domain_owner,
	    inp->inp_necp_attributes.inp_domain_context,
	    inp->inp_necp_attributes.inp_tracker_domain,
	    inp->inp_necp_attributes.inp_account,
	    so->so_flags1 & SOF1_KNOWN_TRACKER,
	    so->so_flags1 & SOF1_TRACKER_NON_APP_INITIATED,
	    so->so_flags1 & SOF1_APPROVED_APP_DOMAIN);

	if (necp_debug) {
		NECPLOG(LOG_DEBUG, "Set on socket: Domain <%s> Domain owner <%s> Domain context <%s> Tracker domain <%s> Account <%s> ",
		    inp->inp_necp_attributes.inp_domain,
		    inp->inp_necp_attributes.inp_domain_owner,
		    inp->inp_necp_attributes.inp_domain_context,
		    inp->inp_necp_attributes.inp_tracker_domain,
		    inp->inp_necp_attributes.inp_account);
	}
fail:
	if (buffer != NULL) {
		kfree_data(buffer, valsize + 1);
	}
	return error;
}

void *
necp_create_nexus_assign_message(uuid_t nexus_instance, u_int32_t nexus_port, void *key, uint32_t key_length,
    struct necp_client_endpoint *local_endpoint, struct necp_client_endpoint *remote_endpoint, struct ether_addr *local_ether_addr,
    u_int32_t flow_adv_index, void *flow_stats, size_t *message_length)
{
	u_int8_t *buffer = NULL;
	u_int8_t *cursor = NULL;
	size_t valsize = 0;
	bool has_nexus_assignment = FALSE;

	if (!uuid_is_null(nexus_instance)) {
		has_nexus_assignment = TRUE;
		valsize += sizeof(struct necp_tlv_header) + sizeof(uuid_t);
		valsize += sizeof(struct necp_tlv_header) + sizeof(u_int32_t);
	}
	if (flow_adv_index != NECP_FLOWADV_IDX_INVALID) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(u_int32_t);
	}
	if (key != NULL && key_length > 0) {
		valsize += sizeof(struct necp_tlv_header) + key_length;
	}
	if (local_endpoint != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(struct necp_client_endpoint);
	}
	if (remote_endpoint != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(struct necp_client_endpoint);
	}
	if (local_ether_addr != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(struct ether_addr);
	}
	if (flow_stats != NULL) {
		valsize += sizeof(struct necp_tlv_header) + sizeof(void *);
	}
	if (valsize == 0) {
		return NULL;
	}

	buffer = kalloc_data(valsize, Z_WAITOK | Z_ZERO);
	if (buffer == NULL) {
		return NULL;
	}

	cursor = buffer;
	if (has_nexus_assignment) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_INSTANCE, sizeof(uuid_t), nexus_instance, buffer, valsize);
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_PORT, sizeof(u_int32_t), &nexus_port, buffer, valsize);
	}
	if (flow_adv_index != NECP_FLOWADV_IDX_INVALID) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_PORT_FLOW_INDEX, sizeof(u_int32_t), &flow_adv_index, buffer, valsize);
	}
	if (key != NULL && key_length > 0) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_PARAMETER_NEXUS_KEY, key_length, key, buffer, valsize);
	}
	if (local_endpoint != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_LOCAL_ENDPOINT, sizeof(struct necp_client_endpoint), local_endpoint, buffer, valsize);
	}
	if (remote_endpoint != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_REMOTE_ENDPOINT, sizeof(struct necp_client_endpoint), remote_endpoint, buffer, valsize);
	}
	if (local_ether_addr != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_LOCAL_ETHER_ADDR, sizeof(struct ether_addr), local_ether_addr, buffer, valsize);
	}
	if (flow_stats != NULL) {
		cursor = necp_buffer_write_tlv(cursor, NECP_CLIENT_RESULT_NEXUS_FLOW_STATS, sizeof(void *), &flow_stats, buffer, valsize);
	}

	*message_length = valsize;

	return buffer;
}

void
necp_inpcb_remove_cb(struct inpcb *inp)
{
	if (!uuid_is_null(inp->necp_client_uuid)) {
		necp_client_unregister_socket_flow(inp->necp_client_uuid, inp);
		uuid_clear(inp->necp_client_uuid);
	}
}

void
necp_inpcb_dispose(struct inpcb *inp)
{
	necp_inpcb_remove_cb(inp); // Clear out socket registrations if not yet done
	if (inp->inp_necp_attributes.inp_domain != NULL) {
		kfree_data_addr(inp->inp_necp_attributes.inp_domain);
		inp->inp_necp_attributes.inp_domain = NULL;
	}
	if (inp->inp_necp_attributes.inp_account != NULL) {
		kfree_data_addr(inp->inp_necp_attributes.inp_account);
		inp->inp_necp_attributes.inp_account = NULL;
	}
	if (inp->inp_necp_attributes.inp_domain_owner != NULL) {
		kfree_data_addr(inp->inp_necp_attributes.inp_domain_owner);
		inp->inp_necp_attributes.inp_domain_owner = NULL;
	}
	if (inp->inp_necp_attributes.inp_domain_context != NULL) {
		kfree_data_addr(inp->inp_necp_attributes.inp_domain_context);
		inp->inp_necp_attributes.inp_domain_context = NULL;
	}
	if (inp->inp_necp_attributes.inp_tracker_domain != NULL) {
		kfree_data_addr(inp->inp_necp_attributes.inp_tracker_domain);
		inp->inp_necp_attributes.inp_tracker_domain = NULL;
	}
}

void
necp_mppcb_dispose(struct mppcb *mpp)
{
	if (!uuid_is_null(mpp->necp_client_uuid)) {
		necp_client_unregister_multipath_cb(mpp->necp_client_uuid, mpp);
		uuid_clear(mpp->necp_client_uuid);
	}

	if (mpp->inp_necp_attributes.inp_domain != NULL) {
		kfree_data_addr(mpp->inp_necp_attributes.inp_domain);
		mpp->inp_necp_attributes.inp_domain = NULL;
	}
	if (mpp->inp_necp_attributes.inp_account != NULL) {
		kfree_data_addr(mpp->inp_necp_attributes.inp_account);
		mpp->inp_necp_attributes.inp_account = NULL;
	}
	if (mpp->inp_necp_attributes.inp_domain_owner != NULL) {
		kfree_data_addr(mpp->inp_necp_attributes.inp_domain_owner);
		mpp->inp_necp_attributes.inp_domain_owner = NULL;
	}
	if (mpp->inp_necp_attributes.inp_tracker_domain != NULL) {
		kfree_data_addr(mpp->inp_necp_attributes.inp_tracker_domain);
		mpp->inp_necp_attributes.inp_tracker_domain = NULL;
	}
}

/// Module init

void
necp_client_init(void)
{
	necp_flow_size = sizeof(struct necp_client_flow);
	necp_flow_cache = mcache_create(NECP_FLOW_ZONE_NAME, necp_flow_size, sizeof(uint64_t), 0, MCR_SLEEP);
	if (necp_flow_cache == NULL) {
		panic("mcache_create(necp_flow_cache) failed");
		/* NOTREACHED */
	}

	necp_flow_registration_size = sizeof(struct necp_client_flow_registration);
	necp_flow_registration_cache = mcache_create(NECP_FLOW_REGISTRATION_ZONE_NAME, necp_flow_registration_size, sizeof(uint64_t), 0, MCR_SLEEP);
	if (necp_flow_registration_cache == NULL) {
		panic("mcache_create(necp_client_flow_registration) failed");
		/* NOTREACHED */
	}

	necp_client_update_tcall = thread_call_allocate_with_options(necp_update_all_clients_callout, NULL,
	    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	VERIFY(necp_client_update_tcall != NULL);
#if SKYWALK

	necp_client_collect_stats_tcall = thread_call_allocate_with_options(necp_collect_stats_client_callout, NULL,
	    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	VERIFY(necp_client_collect_stats_tcall != NULL);

	necp_close_empty_arenas_tcall = thread_call_allocate_with_options(necp_close_empty_arenas_callout, NULL,
	    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	VERIFY(necp_close_empty_arenas_tcall != NULL);
#endif /* SKYWALK */

	LIST_INIT(&necp_fd_list);
	LIST_INIT(&necp_fd_observer_list);
	LIST_INIT(&necp_collect_stats_flow_list);

	RB_INIT(&necp_client_global_tree);
	RB_INIT(&necp_client_flow_global_tree);
}

void
necp_client_reap_caches(boolean_t purge)
{
	mcache_reap_now(necp_flow_cache, purge);
	mcache_reap_now(necp_flow_registration_cache, purge);
}

#if SKYWALK
pid_t
necp_client_get_proc_pid_from_arena_info(struct skmem_arena_mmap_info *arena_info)
{
	ASSERT((arena_info->ami_arena->ar_type == SKMEM_ARENA_TYPE_NECP) || (arena_info->ami_arena->ar_type == SKMEM_ARENA_TYPE_SYSTEM));

	if (arena_info->ami_arena->ar_type == SKMEM_ARENA_TYPE_NECP) {
		struct necp_arena_info *nai = container_of(arena_info, struct necp_arena_info, nai_mmap);
		return nai->nai_proc_pid;
	} else {
		struct necp_fd_data *fd_data = container_of(arena_info, struct necp_fd_data, sysctl_mmap);
		return fd_data->proc_pid;
	}
}
#endif /* !SKYWALK */
