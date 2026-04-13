/*
 * Copyright (c) 2017-2023 Apple Inc. All rights reserved.
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
#include <sys/time.h>
#include <sys/mcache.h>
#include <sys/malloc.h>
#include <sys/kauth.h>
#include <sys/kern_event.h>
#include <sys/bitstring.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/codesign.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#include <libkern/libkern.h>

#include <net/kpi_interface.h>
#include <net/if_var.h>
#include <net/if_ports_used.h>
#include <net/net_sysctl.h>
#include <net/dlil.h>
#include <net/net_kev.h>

#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>

#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <skywalk/namespace/netns.h>
#endif /* SKYWALK */

#include <stdbool.h>

#include <string.h>

#define ESP_HDR_SIZE 4
#define PORT_ISAKMP 500
#define PORT_ISAKMP_NATT 4500   /* rfc3948 */

#define IF_XNAME(ifp) ((ifp) != NULL ? (ifp)->if_xname : (const char * __null_terminated)"")

extern bool IOPMCopySleepWakeUUIDKey(char *buffer, size_t buf_len);

SYSCTL_DECL(_net_link_generic_system);

SYSCTL_NODE(_net_link_generic_system, OID_AUTO, port_used,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "if port used");

struct if_ports_used_stats if_ports_used_stats = {};
static int sysctl_if_ports_used_stats SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, stats,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_if_ports_used_stats, "S,struct if_ports_used_stats", "");

static uuid_t current_wakeuuid;
SYSCTL_OPAQUE(_net_link_generic_system_port_used, OID_AUTO, current_wakeuuid,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    current_wakeuuid, sizeof(uuid_t), "S,uuid_t", "");

static int sysctl_net_port_info_list SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, list,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    sysctl_net_port_info_list, "S,xnpigen", "");

static int use_test_wakeuuid = 0;
static uuid_t test_wakeuuid;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_link_generic_system_port_used, OID_AUTO, use_test_wakeuuid,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &use_test_wakeuuid, 0, "");

static int sysctl_new_test_wakeuuid SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, new_test_wakeuuid,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_new_test_wakeuuid, "S,uuid_t", "");

static int sysctl_clear_test_wakeuuid SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, clear_test_wakeuuid,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_clear_test_wakeuuid, "S,uuid_t", "");

SYSCTL_OPAQUE(_net_link_generic_system_port_used, OID_AUTO, test_wakeuuid,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    test_wakeuuid, sizeof(uuid_t), "S,uuid_t", "");

/*
 * use_fake_lpw is used for testing only
 */
#define FAKE_LPW_OFF            0 /* fake LPW off */
#define FAKE_LPW_ON             1 /* use fake LPW until full AP wake */
#define FAKE_LPW_ALWAYS_ON      2 /* permanent fake LPW mode */

static int use_fake_lpw = 0;
static int sysctl_use_fake_lpw SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, use_fake_lpw,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &use_fake_lpw, 0, &sysctl_use_fake_lpw, "I", "");

bool fake_lpw_mode_is_set = false;

SYSCTL_NODE(_net_link_generic_system_port_used, OID_AUTO, mark_wake_packet,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "if port used");

static int sysctl_mark_wake_packet_port SYSCTL_HANDLER_ARGS;
static int sysctl_mark_wake_packet_if SYSCTL_HANDLER_ARGS;

static int mark_wake_packet_local_port = 0;
SYSCTL_PROC(_net_link_generic_system_port_used_mark_wake_packet, OID_AUTO, local_port,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &mark_wake_packet_local_port, 0, &sysctl_mark_wake_packet_port, "I", "");

static int mark_wake_packet_remote_port = 0;
SYSCTL_PROC(_net_link_generic_system_port_used_mark_wake_packet, OID_AUTO, remote_port,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &mark_wake_packet_remote_port, 0, &sysctl_mark_wake_packet_port, "I", "");

static int mark_wake_packet_ipproto = 0;
SYSCTL_INT(_net_link_generic_system_port_used_mark_wake_packet, OID_AUTO, ipproto,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &mark_wake_packet_ipproto, 0, "");

static char mark_wake_packet_if[IFNAMSIZ];
SYSCTL_PROC(_net_link_generic_system_port_used_mark_wake_packet, OID_AUTO, if,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_mark_wake_packet_if, "A", "");

#endif /* (DEVELOPMENT || DEBUG) */

static int sysctl_get_ports_used SYSCTL_HANDLER_ARGS;
SYSCTL_NODE(_net_link_generic_system, OID_AUTO, get_ports_used,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    sysctl_get_ports_used, "");

int if_ports_used_verbose = 0;
SYSCTL_INT(_net_link_generic_system_port_used, OID_AUTO, verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_ports_used_verbose, 0, "");

struct timeval wakeuuid_not_set_last_time;
int sysctl_wakeuuid_not_set_last_time SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    wakeuuid_not_set_last_time, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_wakeuuid_not_set_last_time, "S,timeval", "");

char wakeuuid_not_set_last_if[IFXNAMSIZ];
int sysctl_wakeuuid_not_set_last_if SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    wakeuuid_not_set_last_if, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_wakeuuid_not_set_last_if, "A", "");

struct timeval wakeuuid_last_update_time;
int sysctl_wakeuuid_last_update_time SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    wakeuuid_last_update_time, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_wakeuuid_last_update_time, "S,timeval", "");

int ports_used_include_boundif = 0;
int sysctl_get_ports_used_include_boundif SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    with_boundif, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_get_ports_used_include_boundif, "I", "");

static bool            last_wake_phy_if_set = false;
static char            last_wake_phy_if_name[IFNAMSIZ]; /* name + unit */
static uint32_t        last_wake_phy_if_family;
static uint32_t        last_wake_phy_if_subfamily;
static uint32_t        last_wake_phy_if_functional_type;
static bool            last_wake_phy_if_delay_wake_pkt = false;
static bool            last_wake_phy_if_lpw = false;

static bool has_notified_wake_pkt = false;
static bool has_notified_unattributed_wake = false;

static bool has_requested_full_AP_wake = false;

static uint32_t wake_attribution_gencnt = 0; /* wrapping OK */

static LCK_GRP_DECLARE(net_port_entry_head_lock_group, "net port entry lock");
static LCK_RW_DECLARE(net_port_entry_head_lock, &net_port_entry_head_lock_group);


struct net_port_entry {
	SLIST_ENTRY(net_port_entry)     npe_list_next;
	TAILQ_ENTRY(net_port_entry)     npe_hash_next;
	uint32_t                        npe_wake_gencnt;
	struct net_port_info            npe_npi;
};

static KALLOC_TYPE_DEFINE(net_port_entry_zone, struct net_port_entry, NET_KT_DEFAULT);

static SLIST_HEAD(net_port_entry_list, net_port_entry) net_port_entry_list =
    SLIST_HEAD_INITIALIZER(&net_port_entry_list);

struct timeval wakeuiid_last_check;

/*
 * Hashing of the net_port_entry list is based on the local port
 *
 * The hash masks uses the least significant bits so we have to use host byte order
 * when applying the mask because the LSB have more entropy that the MSB (most local ports
 * are in the high dynamic port range)
 */
#define NPE_HASH_BUCKET_COUNT 32
#define NPE_HASH_MASK (NPE_HASH_BUCKET_COUNT - 1)
#define NPE_HASH_VAL(_lport) (ntohs(_lport) & NPE_HASH_MASK)
#define NPE_HASH_HEAD(_lport) (&net_port_entry_hash_table[NPE_HASH_VAL(_lport)])

static TAILQ_HEAD(net_port_entry_hash_table, net_port_entry) * __indexable net_port_entry_hash_table = NULL;

/*
 * For some types of physical interface we need to delay the notification of wake packet events
 * until a user land interface controller confirms the AP wake was caused by its packet
 */
struct net_port_info_wake_pkt_event {
	uint32_t                npi_wp_code;
	uint32_t                npi_wp_flags;
	union {
		struct net_port_info_wake_event _npi_ev_wake_pkt_attributed;
		struct net_port_info_una_wake_event _npi_ev_wake_pkt_unattributed;
	} npi_ev_wake_pkt_;
};

#define npi_ev_wake_pkt_attributed npi_ev_wake_pkt_._npi_ev_wake_pkt_attributed
#define npi_ev_wake_pkt_unattributed npi_ev_wake_pkt_._npi_ev_wake_pkt_unattributed

int sysctl_wake_pkt_event_notify SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, wake_pkt_event_notify,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED | CTLFLAG_ANYBODY, 0, 0,
    sysctl_wake_pkt_event_notify, "I", "");

/* Bitmap of the interface families to delay the notification of wake packet events */
static uint32_t npi_wake_packet_event_delay_if_families = 0;

/* How many interfaces families are supported */
#define NPI_MAX_IF_FAMILY_BITS 32

int sysctl_wake_pkt_event_delay_if_families SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, wake_pkt_event_delay_if_families,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_ANYBODY, 0, 0,
    sysctl_wake_pkt_event_delay_if_families, "I", "");

/* last_wake_pkt_event is informational */
static struct net_port_info_wake_pkt_event last_wake_pkt_event;

/*
 * delay_wake_pkt_event hold the current wake packet event that is delayed waiting for
 * confirmation from a userspace agent
 * It can be overwritten as a wake packet makes its way up the stack
 */
static struct net_port_info_wake_pkt_event delay_wake_pkt_event;

int sysctl_last_attributed_wake_event SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    last_attributed_wake_event, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_last_attributed_wake_event, "S,net_port_info_wake_event", "");

int sysctl_last_unattributed_wake_event SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    last_unattributed_wake_event, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_last_unattributed_wake_event, "S,net_port_info_una_wake_event", "");

os_log_t wake_packet_log_handle = NULL;

static bool is_wake_pkt_event_delay(uint32_t ifrtype);

static bool
_if_need_delayed_wake_pkt_event_inner(struct ifnet *ifp)
{
	if (IOPMIsLPWMode()) {
		return false;
	}
	if ((ifp->if_xflags & IFXF_DELAYWAKEPKTEVENT) != 0 ||
	    is_wake_pkt_event_delay(ifp->if_family)) {
		return true;
	}
	return false;
}

static bool
if_need_delayed_wake_pkt_event(struct ifnet *ifp)
{
	if (ifp != NULL) {
		if (_if_need_delayed_wake_pkt_event_inner(ifp) == true) {
			return true;
		}
		if (ifp->if_delegated.ifp != NULL) {
			return _if_need_delayed_wake_pkt_event_inner(ifp->if_delegated.ifp);
		}
	}
	return false;
}

/*
 * Initialize IPv4 source address hash table.
 */
void
if_ports_used_init(void)
{
	if (net_port_entry_hash_table != NULL) {
		return;
	}

	wake_packet_log_handle = os_log_create("com.apple.xnu.net.wake_packet", "");

	net_port_entry_hash_table = zalloc_permanent(
		NPE_HASH_BUCKET_COUNT * sizeof(*net_port_entry_hash_table),
		ZALIGN_PTR);
}

/*
 * Maximum depth for following delegate interface chain.
 * In practice, delegation chains should be very short (1-2 levels),
 * so this limit prevents infinite loops from circular references.
 */
#define IF_DELEGATE_MAX_DEPTH 4

/*
 * A NULL ifp is used to check LPW mode -- fake or real -- on any interface
 */
static bool
if_is_lpw_enabled_internal(struct ifnet *ifp, uint32_t depth)
{
	/* IOKit may take a while to exit AOT mode */
	if (has_requested_full_AP_wake == true) {
		return false;
	}

	/* Prevent infinite recursion from circular delegation */
	if (depth >= IF_DELEGATE_MAX_DEPTH) {
		if (if_ports_used_verbose > 0) {
			os_log(wake_packet_log_handle,
			    "if_is_lpw_enabled: max delegation depth %u exceeded for %s",
			    IF_DELEGATE_MAX_DEPTH, IF_XNAME(ifp));
		}
		return false;
	}

#if (DEBUG || DEVELOPMENT)
	/* This is the fake version of IOPMIsLPWMode */
	if (__improbable(use_fake_lpw != FAKE_LPW_OFF)) {
		if (ifp == NULL) {
			return true;
		}

		/*
		 * Ignore packets on interfaces that are not LPW aware
		 */
		if ((ifp->if_xflags & IFXF_LOW_POWER_WAKE) == 0) {
			/*
			 * Follow the delegate
			 */
			if (ifp->if_delegated.ifp != NULL) {
				return if_is_lpw_enabled_internal(ifp->if_delegated.ifp, depth + 1);
			}
			if (if_ports_used_verbose > 0) {
				os_log(wake_packet_log_handle, "if_is_lpw_enabled %s off", IF_XNAME(ifp));
			}
			return false;
		}

		if (strlcmp(mark_wake_packet_if, IF_XNAME(ifp), IFNAMSIZ) == 0) {
			return true;
		}

		/* In fake mode, ignore packets from other interfaces */
		return false;
	}
#endif /* (DEBUG || DEVELOPMENT) */

	if (IOPMIsLPWMode()) {
		/*
		 * Ignore packets on interfaces that are not LPW aware
		 */
		if (ifp != NULL && (ifp->if_xflags & IFXF_LOW_POWER_WAKE) == 0) {
			/*
			 * Follow the delegate
			 */
			if (ifp->if_delegated.ifp != NULL) {
				return if_is_lpw_enabled_internal(ifp->if_delegated.ifp, depth + 1);
			}
			if (if_ports_used_verbose > 0) {
				os_log(wake_packet_log_handle, "if_is_lpw_enabled %s off", IF_XNAME(ifp));
			}
			return false;
		}
		return true;
	}


	return false;
}

/*
 * We use if_is_lpw_enabled() to know if a packet comes from an interface that
 * has LPW enable to implement the core LPW packet processing logic.
 *
 * IOPMIsLPWMode() simply tells the kernel is in LPW mode and we use if for example
 * to set the lpw flag in the packet capture metadata. Packets from non-LPW inteface
 * may be in transit whrn the AP wakes up.
 *
 * Passing a NULL ifp is equivalent to calling IOPMIsLPWMode() but also checks fake LPW
 *
 * For code clarity one has to use is_net_lpw_mode() instead of NULL to if_is_lpw_enabled()
 */
bool
if_is_lpw_enabled(struct ifnet *ifp)
{
	return if_is_lpw_enabled_internal(ifp, 0);
}

bool
is_net_lpw_mode(void)
{
	return if_is_lpw_enabled_internal(NULL, 0);
}

__attribute__((noinline))
void
if_exit_lpw(struct ifnet *ifp, const char *lpw_exit_reason)
{
	if (ifp == NULL) {
		return;
	}

#if (DEBUG || DEVELOPMENT)
	if (use_fake_lpw != 0) {
		switch (use_fake_lpw) {
		case FAKE_LPW_ON:
			use_fake_lpw = FAKE_LPW_OFF;
			break;
		case FAKE_LPW_ALWAYS_ON:
			return;
		default:
			break;
		}
		if (has_requested_full_AP_wake == true) {
			return;
		}
	}
#else /* (DEBUG || DEVELOPMENT) */
	if (has_requested_full_AP_wake == true || !IOPMIsLPWMode()) {
		return;
	}
#endif /* (DEBUG || DEVELOPMENT) */

	has_requested_full_AP_wake = true;

	if_ports_used_stats.ifpu_lpw_to_full_wake++;
	os_log(wake_packet_log_handle, "if_exit_lpw: LPW to Full Wake requested on %s reason %s",
	    IF_XNAME(ifp), lpw_exit_reason);

	/* Post kernel event for LPW to full wake transition */
	struct net_event_data ev_data;

	bzero(&ev_data, sizeof(ev_data));
	ev_data.if_family = ifp->if_family;
	ev_data.if_unit = ifp->if_unit;
	strlcpy(ev_data.if_name, IF_XNAME(ifp), sizeof(ev_data.if_name));

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_LPW_FULL_WAKE,
	    &ev_data, sizeof(ev_data), TRUE);

#if (DEBUG || DEVELOPMENT)
	if (use_fake_lpw == FAKE_LPW_ALWAYS_ON) {
		return;
	}
#endif /* (DEBUG || DEVELOPMENT) */

	IOPMNetworkStackFullWake(kIOPMNetworkStackFullWakeFlag, "Network.ConnectionNotIdle");
}

static void
net_port_entry_list_clear(void)
{
	struct net_port_entry *npe;

	LCK_RW_ASSERT(&net_port_entry_head_lock, LCK_RW_ASSERT_EXCLUSIVE);

	while ((npe = SLIST_FIRST(&net_port_entry_list)) != NULL) {
		SLIST_REMOVE_HEAD(&net_port_entry_list, npe_list_next);
		TAILQ_REMOVE(NPE_HASH_HEAD(npe->npe_npi.npi_local_port), npe, npe_hash_next);

		zfree(net_port_entry_zone, npe);
	}

	for (int i = 0; i < NPE_HASH_BUCKET_COUNT; i++) {
		VERIFY(TAILQ_EMPTY(&net_port_entry_hash_table[i]));
	}

	if_ports_used_stats.ifpu_npe_count = 0;
	if_ports_used_stats.ifpu_wakeuid_gen++;
}

static bool
get_test_wake_uuid(uuid_string_t wakeuuid_str)
{
	if (!uuid_is_null(test_wakeuuid)) {
		if (wakeuuid_str != NULL) {
			uuid_unparse(test_wakeuuid, wakeuuid_str);
		}
		return true;
	}

	return false;
}

static bool
is_wakeuuid_set(void)
{
	if (__improbable(use_test_wakeuuid) && !uuid_is_null(test_wakeuuid)) {
		return true;
	}

	/*
	 * IOPMCopySleepWakeUUIDKey() tells if SleepWakeUUID is currently set
	 * That means we are currently in a sleep/wake cycle
	 */
	return IOPMCopySleepWakeUUIDKey(NULL, 0);
}

/*
 * Called both when transitioning to sleep from:
 *  - full wake
 *  - AOT wake (i.e. LPW)
 */
static void
if_ports_reset_wake_attribution_state(void)
{
	has_notified_wake_pkt = false;
	has_notified_unattributed_wake = false;

	memset(&last_wake_pkt_event, 0, sizeof(last_wake_pkt_event));
	memset(&delay_wake_pkt_event, 0, sizeof(delay_wake_pkt_event));

	last_wake_phy_if_set = false;
	memset(&last_wake_phy_if_name, 0, sizeof(last_wake_phy_if_name));
	last_wake_phy_if_family = IFRTYPE_FAMILY_ANY;
	last_wake_phy_if_subfamily = IFRTYPE_SUBFAMILY_ANY;
	last_wake_phy_if_functional_type = IFRTYPE_FUNCTIONAL_UNKNOWN;
	last_wake_phy_if_delay_wake_pkt = false;
	last_wake_phy_if_lpw = false;

	has_requested_full_AP_wake = false;
	wake_attribution_gencnt += 1;

#if (DEVELOPMENT || DEBUG)
	fake_lpw_mode_is_set = false;
#endif /* (DEVELOPMENT || DEBUG) */

	os_log(wake_packet_log_handle, "if_ports_reset_wake_attribution_state gencnt %u",
	    wake_attribution_gencnt);
}

void
if_ports_used_update_wakeuuid(struct ifnet *ifp)
{
	uuid_t wakeuuid;
	bool wakeuuid_is_set = false;
	bool updated = false;
	uuid_string_t wakeuuid_str;

	uuid_clear(wakeuuid);

	if (__improbable(use_test_wakeuuid)) {
		wakeuuid_is_set = get_test_wake_uuid(wakeuuid_str);
	} else {
		wakeuuid_is_set = IOPMCopySleepWakeUUIDKey(wakeuuid_str,
		    sizeof(wakeuuid_str));
	}

	if (wakeuuid_is_set) {
		if (uuid_parse(wakeuuid_str, wakeuuid) != 0) {
			os_log(wake_packet_log_handle,
			    "if_ports_used_update_wakeuuid: IOPMCopySleepWakeUUIDKey got bad value %s\n",
			    wakeuuid_str);
			wakeuuid_is_set = false;
		}
	}

	if (!wakeuuid_is_set) {
		if (ifp != NULL) {
			if (if_ports_used_verbose > 0) {
				os_log_info(wake_packet_log_handle,
				    "if_ports_used_update_wakeuuid: SleepWakeUUID not set, "
				    "don't update the port list for %s\n",
				    ifp != NULL ? if_name(ifp) : "");
			}
			if_ports_used_stats.ifpu_wakeuuid_not_set_count += 1;
			microtime(&wakeuuid_not_set_last_time);
			strlcpy(wakeuuid_not_set_last_if, if_name(ifp),
			    sizeof(wakeuuid_not_set_last_if));
		}
		return;
	}

	lck_rw_lock_exclusive(&net_port_entry_head_lock);
	if (uuid_compare(wakeuuid, current_wakeuuid) != 0) {
		if (last_wake_phy_if_delay_wake_pkt) {
			if_ports_used_stats.ifpu_delayed_wake_event_undelivered++;
		}

		net_port_entry_list_clear();
		uuid_copy(current_wakeuuid, wakeuuid);
		microtime(&wakeuuid_last_update_time);
		updated = true;

		if_ports_reset_wake_attribution_state();
	}
	/*
	 * Record the time last checked
	 */
	microuptime(&wakeuiid_last_check);
	lck_rw_unlock_exclusive(&net_port_entry_head_lock);

	if (updated && if_ports_used_verbose > 0) {
		uuid_string_t uuid_str;

		uuid_unparse(current_wakeuuid, uuid_str);
		os_log(wake_packet_log_handle, "if_ports_used_update_wakeuuid: current wakeuuid %s for %s",
		    uuid_str, ifp != NULL ? if_name(ifp) : "");
	}
}

void
IOPMNetworkStackWillSleepFromAOT(void)
{
	/*
	 * We do not take a lock because we assume there won't be any concurrent
	 * power state event when going to sleep from AOT
	 */
	if_ports_reset_wake_attribution_state();

	if (if_ports_used_verbose > 0) {
		os_log(wake_packet_log_handle, "");
	}
}

static bool
net_port_info_equal(const struct net_port_info *x,
    const struct net_port_info *y)
{
	ASSERT(x != NULL && y != NULL);

	if (x->npi_if_index == y->npi_if_index &&
	    x->npi_local_port == y->npi_local_port &&
	    x->npi_foreign_port == y->npi_foreign_port &&
	    x->npi_owner_pid == y->npi_owner_pid &&
	    x->npi_effective_pid == y->npi_effective_pid &&
	    x->npi_flags == y->npi_flags &&
	    memcmp(&x->npi_local_addr_, &y->npi_local_addr_,
	    sizeof(union in_addr_4_6)) == 0 &&
	    memcmp(&x->npi_foreign_addr_, &y->npi_foreign_addr_,
	    sizeof(union in_addr_4_6)) == 0) {
		return true;
	}
	return false;
}

static bool
net_port_info_has_entry(const struct net_port_info *npi)
{
	struct net_port_entry *npe;
	bool found = false;
	int32_t count = 0;

	LCK_RW_ASSERT(&net_port_entry_head_lock, LCK_RW_ASSERT_HELD);

	TAILQ_FOREACH(npe, NPE_HASH_HEAD(npi->npi_local_port), npe_hash_next) {
		count += 1;
		if (net_port_info_equal(&npe->npe_npi, npi)) {
			found = true;
			break;
		}
	}
	if_ports_used_stats.ifpu_npi_hash_search_total += count;
	if (count > if_ports_used_stats.ifpu_npi_hash_search_max) {
		if_ports_used_stats.ifpu_npi_hash_search_max = count;
	}

	return found;
}

/*
 * Search the port entry list for an entry with the given PID and retrieve
 * the platform binary flag and optionally the owner UUID.
 *
 * Parameters:
 *   pid: Process ID to search for
 *   ext_flags: Pointer to ext_flags to update with NPIXF_PLATFORMBINARY if found
 *   owner_uuid: Optional pointer to uuid_t to copy the owner UUID into (can be NULL)
 *
 * Returns:
 *   true if a matching entry was found, false otherwise
 *
 * Must be called with net_port_entry_head_lock held (SHARED or EXCLUSIVE)
 */
static bool
net_port_info_get_pid_info_from_list(pid_t pid, uint16_t *ext_flags, uuid_t *owner_uuid)
{
	struct net_port_entry *npe;
	bool found = false;

	LCK_RW_ASSERT(&net_port_entry_head_lock, LCK_RW_ASSERT_HELD);

	if (pid == 0) {
		return false;
	}

	SLIST_FOREACH(npe, &net_port_entry_list, npe_list_next) {
		if (npe->npe_npi.npi_owner_pid == pid) {
			/* Copy platform binary flag if set */
			if (npe->npe_npi.npi_ext_flags & NPIXF_PLATFORMBINARY) {
				*ext_flags |= NPIXF_PLATFORMBINARY;
			}
			/* Copy owner UUID if caller requested it */
			if (owner_uuid != NULL) {
				uuid_copy(*owner_uuid, npe->npe_npi.npi_owner_uuid);
			}
			found = true;
			break;
		}
	}

	return found;
}

static bool
net_port_info_add_entry(const struct net_port_info *npi)
{
	struct net_port_entry   *npe = NULL;
	uint32_t num = 0;
	bool entry_added = false;

	ASSERT(npi != NULL);

	if (__improbable(is_wakeuuid_set() == false)) {
		if_ports_used_stats.ifpu_npi_not_added_no_wakeuuid++;
		if (if_ports_used_verbose > 0) {
			os_log(wake_packet_log_handle, "%s: wakeuuid not set not adding "
			    "port: %u flags: 0x%xif: %u pid: %u epid %u",
			    __func__,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
		return false;
	}

	npe = zalloc_flags(net_port_entry_zone, Z_WAITOK | Z_ZERO);
	if (__improbable(npe == NULL)) {
		os_log(wake_packet_log_handle, "%s: zalloc() failed for "
		    "port: %u flags: 0x%x if: %u pid: %u epid %u",
		    __func__,
		    ntohs(npi->npi_local_port),
		    npi->npi_flags,
		    npi->npi_if_index,
		    npi->npi_owner_pid,
		    npi->npi_effective_pid);
		return false;
	}

	memcpy(&npe->npe_npi, npi, sizeof(npe->npe_npi));

	if (IF_INDEX_IN_RANGE(npe->npe_npi.npi_if_index)) {
		struct ifnet *ifp = ifindex2ifnet[npe->npe_npi.npi_if_index];
		if (ifp != NULL) {
			if (IFNET_IS_COMPANION_LINK(ifp)) {
				npe->npe_npi.npi_flags |= NPIF_COMPLINK;
			}
			if (if_need_delayed_wake_pkt_event(ifp)) {
				npe->npe_npi.npi_flags |= NPIF_DELAYWAKEPKTEVENT;
			}
		}
	}

	lck_rw_lock_exclusive(&net_port_entry_head_lock);

	if (net_port_info_has_entry(npi) == false) {
		SLIST_INSERT_HEAD(&net_port_entry_list, npe, npe_list_next);
		TAILQ_INSERT_HEAD(NPE_HASH_HEAD(npi->npi_local_port), npe, npe_hash_next);
		num = (uint32_t)if_ports_used_stats.ifpu_npe_count++; /* rollover OK */
		entry_added = true;

		if (if_ports_used_stats.ifpu_npe_count > if_ports_used_stats.ifpu_npe_max) {
			if_ports_used_stats.ifpu_npe_max = if_ports_used_stats.ifpu_npe_count;
		}
		if_ports_used_stats.ifpu_npe_total++;

		if (if_ports_used_verbose > 1) {
			os_log(wake_packet_log_handle, "%s: num %u for "
			    "port: %u flags: 0x%x if: %u pid: %u epid %u",
			    __func__,
			    num,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
	} else {
		if_ports_used_stats.ifpu_npe_dup++;
		if (if_ports_used_verbose > 2) {
			os_log(wake_packet_log_handle, "%s: already added "
			    "port: %u flags: 0x%x if: %u pid: %u epid %u",
			    __func__,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
	}

	lck_rw_unlock_exclusive(&net_port_entry_head_lock);

	if (entry_added == false) {
		zfree(net_port_entry_zone, npe);
	}
	return entry_added;
}

#if (DEVELOPMENT || DEBUG)
static int
sysctl_new_test_wakeuuid SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(uuid_t);
		return 0;
	}
	if (req->newptr != USER_ADDR_NULL) {
		uuid_generate(test_wakeuuid);
		if_ports_used_update_wakeuuid(NULL);
	}
	error = SYSCTL_OUT(req, test_wakeuuid,
	    MIN(sizeof(uuid_t), req->oldlen));

	return error;
}

static int
sysctl_clear_test_wakeuuid SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(uuid_t);
		return 0;
	}
	if (req->newptr != USER_ADDR_NULL) {
		uuid_clear(test_wakeuuid);
		if_ports_used_update_wakeuuid(NULL);
	}
	error = SYSCTL_OUT(req, test_wakeuuid,
	    MIN(sizeof(uuid_t), req->oldlen));

	return error;
}

#endif /* (DEVELOPMENT || DEBUG) */

int
sysctl_get_ports_used_include_boundif SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error = 0;
	int val = ports_used_include_boundif;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == USER_ADDR_NULL) {
		return error;
	}

	if (val < 0 || val > 1) {
		return EINVAL;
	}

	ports_used_include_boundif = val;

	os_log(wake_packet_log_handle, "ports_used_include_boundif set to %d",
	    ports_used_include_boundif);

	return error;
}

static int
sysctl_timeval(struct sysctl_req *req, const struct timeval *tv)
{
	if (proc_is64bit(req->p)) {
		struct user64_timeval tv64 = {};

		tv64.tv_sec = tv->tv_sec;
		tv64.tv_usec = tv->tv_usec;
		return SYSCTL_OUT(req, &tv64, sizeof(tv64));
	} else {
		struct user32_timeval tv32 = {};

		tv32.tv_sec = (user32_time_t)tv->tv_sec;
		tv32.tv_usec = tv->tv_usec;
		return SYSCTL_OUT(req, &tv32, sizeof(tv32));
	}
}

int
sysctl_wakeuuid_last_update_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	return sysctl_timeval(req, &wakeuuid_last_update_time);
}

int
sysctl_wakeuuid_not_set_last_time SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	return sysctl_timeval(req, &wakeuuid_not_set_last_time);
}

int
sysctl_wakeuuid_not_set_last_if SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	return SYSCTL_OUT(req, &wakeuuid_not_set_last_if, strbuflen(wakeuuid_not_set_last_if) + 1);
}

int
sysctl_if_ports_used_stats SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	size_t len = sizeof(struct if_ports_used_stats);

	if (req->oldptr != 0) {
		len = MIN(req->oldlen, sizeof(struct if_ports_used_stats));
	}
	return SYSCTL_OUT(req, &if_ports_used_stats, len);
}

static int
sysctl_net_port_info_list SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	struct xnpigen xnpigen;
	struct net_port_entry *npe;

	if ((error = priv_check_cred(kauth_cred_get(),
	    PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0)) != 0) {
		return EPERM;
	}
	lck_rw_lock_shared(&net_port_entry_head_lock);

	if (req->oldptr == USER_ADDR_NULL) {
		/* Add a 25% cushion */
		size_t cnt = (size_t)if_ports_used_stats.ifpu_npe_count;
		cnt += cnt >> 4;
		req->oldidx = sizeof(struct xnpigen) +
		    cnt * sizeof(struct net_port_info);
		goto done;
	}

	memset(&xnpigen, 0, sizeof(struct xnpigen));
	xnpigen.xng_len = sizeof(struct xnpigen);
	xnpigen.xng_gen = (uint32_t)if_ports_used_stats.ifpu_wakeuid_gen;
	uuid_copy(xnpigen.xng_wakeuuid, current_wakeuuid);
	xnpigen.xng_npi_count = (uint32_t)if_ports_used_stats.ifpu_npe_count;
	xnpigen.xng_npi_size = sizeof(struct net_port_info);
	error = SYSCTL_OUT(req, &xnpigen, sizeof(xnpigen));
	if (error != 0) {
		printf("%s: SYSCTL_OUT(xnpigen) error %d\n",
		    __func__, error);
		goto done;
	}

	SLIST_FOREACH(npe, &net_port_entry_list, npe_list_next) {
		error = SYSCTL_OUT(req, &npe->npe_npi,
		    sizeof(struct net_port_info));
		if (error != 0) {
			printf("%s: SYSCTL_OUT(npi) error %d\n",
			    __func__, error);
			goto done;
		}
	}
done:
	lck_rw_unlock_shared(&net_port_entry_head_lock);

	return error;
}

/*
 * Mirror the arguments of ifnet_get_local_ports_extended()
 *  ifindex
 *  protocol
 *  flags
 */
static int
sysctl_get_ports_used SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)
	/*
	 * 3 is the required number of parameters: ifindex, protocol and flags
	 */
	DECLARE_SYSCTL_HANDLER_ARG_ARRAY(int, 3, name, namelen);
	int error = 0;
	int idx;
	protocol_family_t protocol;
	u_int32_t flags;
	ifnet_t ifp = NULL;
	u_int8_t *bitfield = NULL;

	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto done;
	}

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = bitstr_size(IP_PORTRANGE_SIZE);
		goto done;
	}
	if (req->oldlen < bitstr_size(IP_PORTRANGE_SIZE)) {
		error = ENOMEM;
		goto done;
	}
	bitfield = (u_int8_t *) kalloc_data(bitstr_size(IP_PORTRANGE_SIZE),
	    Z_WAITOK | Z_ZERO);
	if (bitfield == NULL) {
		error = ENOMEM;
		goto done;
	}

	idx = name[0];
	protocol = name[1];
	flags = name[2];

	ifnet_head_lock_shared();
	if (IF_INDEX_IN_RANGE(idx)) {
		ifp = ifindex2ifnet[idx];
	}
	ifnet_head_done();

	if (ifp == NULL) {
		error = ENOENT;
		goto done;
	}

	error = ifnet_get_local_ports_extended(ifp, protocol, flags, bitfield);
	if (error != 0) {
		printf("%s: ifnet_get_local_ports_extended() error %d\n",
		    __func__, error);
		goto done;
	}
	error = SYSCTL_OUT(req, bitfield, bitstr_size(IP_PORTRANGE_SIZE));
done:
	if (bitfield != NULL) {
		kfree_data(bitfield, bitstr_size(IP_PORTRANGE_SIZE));
	}
	return error;
}

__private_extern__ bool
if_ports_used_add_inpcb(const uint32_t ifindex, const struct inpcb *inp)
{
	struct net_port_info npi = {};
	struct socket *so = inp->inp_socket;

	/* This is unlikely to happen but better be safe than sorry */
	if (ifindex > UINT16_MAX) {
		os_log(wake_packet_log_handle, "%s: ifindex %u too big", __func__, ifindex);
		return false;
	}

	if (ifindex != 0) {
		npi.npi_if_index = (uint16_t)ifindex;
	} else if (inp->inp_last_outifp != NULL) {
		npi.npi_if_index = (uint16_t)inp->inp_last_outifp->if_index;
	}

	npi.npi_flags |= NPIF_SOCKET;

	npi.npi_timestamp.tv_sec = (int32_t)wakeuiid_last_check.tv_sec;
	npi.npi_timestamp.tv_usec = wakeuiid_last_check.tv_usec;

	if (so->so_options & SO_NOWAKEFROMSLEEP) {
		npi.npi_flags |= NPIF_NOWAKE;
	}

	if (inp->inp_flags2 & INP2_CONNECTION_IDLE) {
		npi.npi_flags |= NPIF_CONNECTION_IDLE;
	}

	if (SOCK_PROTO(so) == IPPROTO_TCP) {
		struct tcpcb *tp = intotcpcb(inp);

		npi.npi_flags |= NPIF_TCP;
		if (tp != NULL && tp->t_state == TCPS_LISTEN) {
			npi.npi_flags |= NPIF_LISTEN;
		}
	} else if (SOCK_PROTO(so) == IPPROTO_UDP) {
		npi.npi_flags |= NPIF_UDP;
	} else {
		os_log(wake_packet_log_handle, "%s: unexpected protocol %u for inp %p", __func__,
		    SOCK_PROTO(inp->inp_socket), inp);
		return false;
	}

	uuid_copy(npi.npi_flow_uuid, inp->necp_client_uuid);

	npi.npi_local_port = inp->inp_lport;
	npi.npi_foreign_port = inp->inp_fport;

	/*
	 * Take in account IPv4 addresses mapped on IPv6
	 */
	if ((inp->inp_vflag & INP_IPV6) != 0 && (inp->inp_flags & IN6P_IPV6_V6ONLY) == 0 &&
	    (inp->inp_vflag & (INP_IPV6 | INP_IPV4)) == (INP_IPV6 | INP_IPV4)) {
		npi.npi_flags |= NPIF_IPV6 | NPIF_IPV4;
		memcpy(&npi.npi_local_addr_in6,
		    &inp->in6p_laddr, sizeof(struct in6_addr));
	} else if (inp->inp_vflag & INP_IPV4) {
		npi.npi_flags |= NPIF_IPV4;
		npi.npi_local_addr_in = inp->inp_laddr;
		npi.npi_foreign_addr_in = inp->inp_faddr;
	} else {
		npi.npi_flags |= NPIF_IPV6;
		memcpy(&npi.npi_local_addr_in6,
		    &inp->in6p_laddr, sizeof(struct in6_addr));
		memcpy(&npi.npi_foreign_addr_in6,
		    &inp->in6p_faddr, sizeof(struct in6_addr));

		/* Clear the embedded scope ID */
		if (IN6_IS_ADDR_LINKLOCAL(&npi.npi_local_addr_in6)) {
			npi.npi_local_addr_in6.s6_addr16[1] = 0;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&npi.npi_foreign_addr_in6)) {
			npi.npi_foreign_addr_in6.s6_addr16[1] = 0;
		}
	}

	npi.npi_owner_pid = so->last_pid;

	if (so->last_pid != 0) {
		proc_name(so->last_pid, npi.npi_owner_pname,
		    sizeof(npi.npi_owner_pname));
		uuid_copy(npi.npi_owner_uuid, so->last_uuid);

		/*
		 * Check if the process is a platform binary.
		 * First check if we already have an entry in the list for this PID.
		 */
		bool found_in_list = false;
		lck_rw_lock_shared(&net_port_entry_head_lock);
		found_in_list = net_port_info_get_pid_info_from_list(so->last_pid, &npi.npi_ext_flags, NULL);
		lck_rw_unlock_shared(&net_port_entry_head_lock);

		if (!found_in_list) {
			proc_t proc = proc_find(so->last_pid);
			if (proc != PROC_NULL) {
				if (csproc_get_platform_binary(proc)) {
					npi.npi_ext_flags |= NPIXF_PLATFORMBINARY;
				}
				proc_rele(proc);
			}
		}
	}

	if (so->so_flags & SOF_DELEGATED) {
		npi.npi_flags |= NPIF_DELEGATED;
		npi.npi_effective_pid = so->e_pid;
		if (so->e_pid != 0) {
			proc_name(so->e_pid, npi.npi_effective_pname,
			    sizeof(npi.npi_effective_pname));
		}
		uuid_copy(npi.npi_effective_uuid, so->e_uuid);
	} else {
		npi.npi_effective_pid = so->last_pid;
		if (so->last_pid != 0) {
			strbufcpy(npi.npi_effective_pname, npi.npi_owner_pname);
		}
		uuid_copy(npi.npi_effective_uuid, so->last_uuid);
	}

	return net_port_info_add_entry(&npi);
}

#if SKYWALK
__private_extern__ bool
if_ports_used_add_flow_entry(const struct flow_entry *fe, const uint32_t ifindex,
    const struct ns_flow_info *nfi, uint32_t ns_flags)
{
	struct net_port_info npi = {};

	/* This is unlikely to happen but better be safe than sorry */
	if (ifindex > UINT16_MAX) {
		os_log(wake_packet_log_handle, "%s: ifindex %u too big", __func__, ifindex);
		return false;
	}
	npi.npi_if_index = (uint16_t)ifindex;

	npi.npi_flags |= NPIF_CHANNEL;

	npi.npi_timestamp.tv_sec = (int32_t)wakeuiid_last_check.tv_sec;
	npi.npi_timestamp.tv_usec = wakeuiid_last_check.tv_usec;

	if (ns_flags & NETNS_NOWAKEFROMSLEEP) {
		npi.npi_flags |= NPIF_NOWAKE;
	}
	if (ns_flags & NETNS_CONNECTION_IDLE) {
		npi.npi_flags |= NPIF_CONNECTION_IDLE;
	}
	if ((ns_flags & NETNS_OWNER_MASK) == NETNS_LISTENER) {
		npi.npi_flags |= NPIF_LISTEN;
	}

	uuid_copy(npi.npi_flow_uuid, nfi->nfi_flow_uuid);

	if (nfi->nfi_protocol == IPPROTO_TCP) {
		npi.npi_flags |= NPIF_TCP;
	} else if (nfi->nfi_protocol == IPPROTO_UDP) {
		npi.npi_flags |= NPIF_UDP;
	} else {
		os_log(wake_packet_log_handle, "%s: unexpected protocol %u for nfi %p",
		    __func__, nfi->nfi_protocol, nfi);
		return false;
	}

	if (nfi->nfi_laddr.sa.sa_family == AF_INET) {
		npi.npi_flags |= NPIF_IPV4;

		npi.npi_local_port = nfi->nfi_laddr.sin.sin_port;
		npi.npi_foreign_port = nfi->nfi_faddr.sin.sin_port;

		npi.npi_local_addr_in = nfi->nfi_laddr.sin.sin_addr;
		npi.npi_foreign_addr_in = nfi->nfi_faddr.sin.sin_addr;
	} else {
		npi.npi_flags |= NPIF_IPV6;

		npi.npi_local_port = nfi->nfi_laddr.sin6.sin6_port;
		npi.npi_foreign_port = nfi->nfi_faddr.sin6.sin6_port;

		memcpy(&npi.npi_local_addr_in6,
		    &nfi->nfi_laddr.sin6.sin6_addr, sizeof(struct in6_addr));
		memcpy(&npi.npi_foreign_addr_in6,
		    &nfi->nfi_faddr.sin6.sin6_addr, sizeof(struct in6_addr));

		/* Clear the embedded scope ID */
		if (IN6_IS_ADDR_LINKLOCAL(&npi.npi_local_addr_in6)) {
			npi.npi_local_addr_in6.s6_addr16[1] = 0;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&npi.npi_foreign_addr_in6)) {
			npi.npi_foreign_addr_in6.s6_addr16[1] = 0;
		}
	}

	npi.npi_owner_pid = nfi->nfi_owner_pid;
	strbufcpy(npi.npi_owner_pname, nfi->nfi_owner_name);

	/*
	 * Get the proc UUID from the pid as the the proc UUID is not present
	 * in the flow_entry.
	 * Also check if the process is a platform binary.
	 * First check if we already have an entry in the list for this PID.
	 * If found, we can get both the platform binary flag AND the UUID
	 * from the existing entry, avoiding the expensive proc_find() call.
	 */
	bool found_in_list = false;
	lck_rw_lock_shared(&net_port_entry_head_lock);
	found_in_list = net_port_info_get_pid_info_from_list(npi.npi_owner_pid, &npi.npi_ext_flags, &npi.npi_owner_uuid);
	lck_rw_unlock_shared(&net_port_entry_head_lock);

	/* Only call proc_find if the PID was not found in the list */
	if (!found_in_list) {
		proc_t proc = proc_find(npi.npi_owner_pid);
		if (proc != PROC_NULL) {
			proc_getexecutableuuid(proc, npi.npi_owner_uuid, sizeof(npi.npi_owner_uuid));
			if (csproc_get_platform_binary(proc)) {
				npi.npi_ext_flags |= NPIXF_PLATFORMBINARY;
			}
			proc_rele(proc);
		}
	}
	if (nfi->nfi_effective_pid != -1) {
		npi.npi_effective_pid = nfi->nfi_effective_pid;
		strbufcpy(npi.npi_effective_pname, nfi->nfi_effective_name);
		uuid_copy(npi.npi_effective_uuid, fe->fe_eproc_uuid);
	} else {
		npi.npi_effective_pid = npi.npi_owner_pid;
		strbufcpy(npi.npi_effective_pname, npi.npi_owner_pname);
		uuid_copy(npi.npi_effective_uuid, npi.npi_owner_uuid);
	}

	return net_port_info_add_entry(&npi);
}

#endif /* SKYWALK */

static void
net_port_info_log_npi(const char *s, const struct net_port_info *npi)
{
	char lbuf[MAX_IPv6_STR_LEN] = {};
	char fbuf[MAX_IPv6_STR_LEN] = {};

	if (npi == NULL) {
		os_log(wake_packet_log_handle, "%s", s);
		return;
	}

	if (npi->npi_flags & NPIF_IPV4) {
		inet_ntop(PF_INET, &npi->npi_local_addr_in.s_addr,
		    lbuf, sizeof(lbuf));
		inet_ntop(PF_INET, &npi->npi_foreign_addr_in.s_addr,
		    fbuf, sizeof(fbuf));
	} else if (npi->npi_flags & NPIF_IPV6) {
		inet_ntop(PF_INET6, &npi->npi_local_addr_in6,
		    lbuf, sizeof(lbuf));
		inet_ntop(PF_INET6, &npi->npi_foreign_addr_in6,
		    fbuf, sizeof(fbuf));
	}
	os_log(wake_packet_log_handle, "%s net_port_info if_index %u arch %s family %s proto %s local %s:%u foreign %s:%u pid: %u epid %u",
	    s != NULL ? s : "",
	    npi->npi_if_index,
	    (npi->npi_flags & NPIF_SOCKET) ? "so" : (npi->npi_flags & NPIF_CHANNEL) ? "ch" : "unknown",
	    (npi->npi_flags & NPIF_IPV4) ? "ipv4" : (npi->npi_flags & NPIF_IPV6) ? "ipv6" : "unknown",
	    npi->npi_flags & NPIF_TCP ? "tcp" : npi->npi_flags & NPIF_UDP ? "udp" :
	    npi->npi_flags & NPIF_ESP ? "esp" : "unknown",
	    lbuf, ntohs(npi->npi_local_port),
	    fbuf, ntohs(npi->npi_foreign_port),
	    npi->npi_owner_pid,
	    npi->npi_effective_pid);
}

/*
 * net_port_info_match_npi() returns true for an exact match that does not have "no wake" set
 */
#define NPI_MATCH_IPV4 (NPIF_IPV4 | NPIF_TCP | NPIF_UDP)
#define NPI_MATCH_IPV6 (NPIF_IPV6 | NPIF_TCP | NPIF_UDP)

static bool
net_port_info_match_npi(struct net_port_entry *npe, const struct net_port_info *in_npi,
    struct net_port_entry **best_match)
{
	if (__improbable(net_wake_pkt_debug > 1)) {
		net_port_info_log_npi("net_port_info_match_npi", &npe->npe_npi);
	}

	/*
	 * The interfaces must match or be both companion link
	 */
	if (npe->npe_npi.npi_if_index != in_npi->npi_if_index &&
	    !((npe->npe_npi.npi_flags & NPIF_COMPLINK) && (in_npi->npi_flags & NPIF_COMPLINK))) {
		return false;
	}

	/*
	 * The local ports and protocols must match
	 */
	if (npe->npe_npi.npi_local_port != in_npi->npi_local_port ||
	    ((npe->npe_npi.npi_flags & NPI_MATCH_IPV4) != (in_npi->npi_flags & NPI_MATCH_IPV4) &&
	    (npe->npe_npi.npi_flags & NPI_MATCH_IPV6) != (in_npi->npi_flags & NPI_MATCH_IPV6))) {
		return false;
	}

	/*
	 * Search stops on an exact match
	 */
	if (npe->npe_npi.npi_foreign_port == in_npi->npi_foreign_port) {
		if ((npe->npe_npi.npi_flags & NPIF_IPV4) && (npe->npe_npi.npi_flags & NPIF_IPV4)) {
			if (in_npi->npi_local_addr_in.s_addr == npe->npe_npi.npi_local_addr_in.s_addr &&
			    in_npi->npi_foreign_addr_in.s_addr == npe->npe_npi.npi_foreign_addr_in.s_addr) {
				if (npe->npe_npi.npi_flags & NPIF_NOWAKE) {
					/*
					 * Do not overwrite an existing match when "no wake" is set
					 */
					if (*best_match == NULL) {
						*best_match = npe;
					}
					return false;
				}
				*best_match = npe;
				return true;
			}
		}
		if ((npe->npe_npi.npi_flags & NPIF_IPV6) && (npe->npe_npi.npi_flags & NPIF_IPV6)) {
			if (memcmp(&npe->npe_npi.npi_local_addr_, &in_npi->npi_local_addr_,
			    sizeof(union in_addr_4_6)) == 0 &&
			    memcmp(&npe->npe_npi.npi_foreign_addr_, &in_npi->npi_foreign_addr_,
			    sizeof(union in_addr_4_6)) == 0) {
				if (npe->npe_npi.npi_flags & NPIF_NOWAKE) {
					/*
					 * Do not overwrite an existing match when "no wake" is set
					 */
					if (*best_match == NULL) {
						*best_match = npe;
					}
					return false;
				}
				*best_match = npe;
				return true;
			}
		}
	}
	/*
	 * Skip connected entries as we are looking for a wildcard match
	 * on the local address and port
	 */
	if (npe->npe_npi.npi_foreign_port != 0) {
		return false;
	}
	/*
	 * Do not overwrite an existing match when "no wake" is set
	 */
	if (*best_match != NULL && (npe->npe_npi.npi_flags & NPIF_NOWAKE) != 0) {
		return false;
	}
	/*
	 * The local address matches: this is our 2nd best match
	 */
	if (memcmp(&npe->npe_npi.npi_local_addr_, &in_npi->npi_local_addr_,
	    sizeof(union in_addr_4_6)) == 0) {
		*best_match = npe;
		return false;
	}

	/*
	 * Only the local port matches, do not override a match
	 * on the local address
	 */
	if (*best_match == NULL) {
		*best_match = npe;
	}
	return false;
}
#undef NPI_MATCH_IPV4
#undef NPI_MATCH_IPV6

/*
 *
 */
static bool
net_port_info_find_match(struct ifnet *ifp, struct net_port_info *in_npi, uint32_t *gencnt)
{
	struct net_port_entry *npe;
	struct net_port_entry * __single best_match = NULL;
	bool found_match = false;

	lck_rw_lock_shared(&net_port_entry_head_lock);

	TAILQ_FOREACH(npe, NPE_HASH_HEAD(in_npi->npi_local_port), npe_hash_next) {
		/*
		 * Search stop on an exact match
		 */
		if (net_port_info_match_npi(npe, in_npi, &best_match)) {
			break;
		}
	}

	if (best_match != NULL) {
		in_npi->npi_flags = best_match->npe_npi.npi_flags;
		in_npi->npi_owner_pid = best_match->npe_npi.npi_owner_pid;
		in_npi->npi_effective_pid = best_match->npe_npi.npi_effective_pid;
		strbufcpy(in_npi->npi_owner_pname, best_match->npe_npi.npi_owner_pname);
		strbufcpy(in_npi->npi_effective_pname, best_match->npe_npi.npi_effective_pname);
		uuid_copy(in_npi->npi_owner_uuid, best_match->npe_npi.npi_owner_uuid);
		uuid_copy(in_npi->npi_effective_uuid, best_match->npe_npi.npi_effective_uuid);

		/*
		 * To avoid issuing duplicate wake packet event within the same wake cycle
		 * we return the current generation count of the entry and then update it to the
		 * current wake generation count.
		 * Use atomic exchange to atomically read old value and write new value.
		 */
		*gencnt = os_atomic_xchg(&best_match->npe_wake_gencnt, wake_attribution_gencnt, relaxed);
		found_match = true;
	}
	lck_rw_unlock_shared(&net_port_entry_head_lock);

	if (__improbable(net_wake_pkt_debug > 0)) {
		if (found_match) {
			net_port_info_log_npi("wake packet match", in_npi);
		} else {
			net_port_info_log_npi("wake packet no match", in_npi);
		}
	}

	if (!found_match && ifp->if_delegated.ifp != NULL) {
		/*
		 * Follow the interface delegation
		 */
		if (if_ports_used_verbose > 0) {
			os_log(wake_packet_log_handle, "net_port_info_find_match %s check on delegated %s",
			    ifp->if_xname, ifp->if_delegated.ifp->if_xname);
		}
		in_npi->npi_if_index = ifp->if_delegated.ifp->if_index;
		found_match = net_port_info_find_match(ifp->if_delegated.ifp, in_npi, gencnt);
	}

	return found_match;
}

#if (DEBUG || DEVELOPMENT)
static void
net_port_info_log_una_wake_event(const char *s, struct net_port_info_una_wake_event *ev)
{
	char lbuf[MAX_IPv6_STR_LEN] = {};
	char fbuf[MAX_IPv6_STR_LEN] = {};

	if (ev->una_wake_pkt_flags & NPIF_IPV4) {
		inet_ntop(PF_INET, &ev->una_wake_pkt_local_addr_._in_a_4.s_addr,
		    lbuf, sizeof(lbuf));
		inet_ntop(PF_INET, &ev->una_wake_pkt_foreign_addr_._in_a_4.s_addr,
		    fbuf, sizeof(fbuf));
	} else if (ev->una_wake_pkt_flags & NPIF_IPV6) {
		inet_ntop(PF_INET6, &ev->una_wake_pkt_local_addr_._in_a_6.s6_addr,
		    lbuf, sizeof(lbuf));
		inet_ntop(PF_INET6, &ev->una_wake_pkt_foreign_addr_._in_a_6.s6_addr,
		    fbuf, sizeof(fbuf));
	}
	os_log(wake_packet_log_handle, "%s if %s (%u) phy_if %s proto %s local %s:%u foreign %s:%u len: %u datalen: %u cflags: 0x%x proto: %u lpw: %d",
	    s != NULL ? s : "",
	    ev->una_wake_pkt_ifname, ev->una_wake_pkt_if_index, ev->una_wake_pkt_phy_ifname,
	    ev->una_wake_pkt_flags & NPIF_TCP ? "tcp" : ev->una_wake_pkt_flags & NPIF_UDP ? "udp" :
	    ev->una_wake_pkt_flags & NPIF_ESP ? "esp" : "unknown",
	    lbuf, ntohs(ev->una_wake_pkt_local_port),
	    fbuf, ntohs(ev->una_wake_pkt_foreign_port),
	    ev->una_wake_pkt_total_len, ev->una_wake_pkt_data_len,
	    ev->una_wake_pkt_control_flags, ev->una_wake_pkt_proto,
	    ev->una_wake_pkt_flags & NPIF_LPW ? 1 : 0);
}

static void
net_port_info_log_wake_event(const char *s, struct net_port_info_wake_event *ev)
{
	char lbuf[MAX_IPv6_STR_LEN] = {};
	char fbuf[MAX_IPv6_STR_LEN] = {};

	if (ev->wake_pkt_flags & NPIF_IPV4) {
		inet_ntop(PF_INET, &ev->wake_pkt_local_addr_._in_a_4.s_addr,
		    lbuf, sizeof(lbuf));
		inet_ntop(PF_INET, &ev->wake_pkt_foreign_addr_._in_a_4.s_addr,
		    fbuf, sizeof(fbuf));
	} else if (ev->wake_pkt_flags & NPIF_IPV6) {
		inet_ntop(PF_INET6, &ev->wake_pkt_local_addr_._in_a_6.s6_addr,
		    lbuf, sizeof(lbuf));
		inet_ntop(PF_INET6, &ev->wake_pkt_foreign_addr_._in_a_6.s6_addr,
		    fbuf, sizeof(fbuf));
	}
	os_log(wake_packet_log_handle, "%s if %s (%u) phy_if %s proto %s local %s:%u foreign %s:%u len: %u datalen: %u cflags: 0x%x proc %s eproc %s idle %d lpw %d",
	    s != NULL ? s : "",
	    ev->wake_pkt_ifname, ev->wake_pkt_if_index, ev->wake_pkt_phy_ifname,
	    ev->wake_pkt_flags & NPIF_TCP ? "tcp" : ev->wake_pkt_flags ? "udp" :
	    ev->wake_pkt_flags & NPIF_ESP ? "esp" : "unknown",
	    lbuf, ntohs(ev->wake_pkt_port),
	    fbuf, ntohs(ev->wake_pkt_foreign_port),
	    ev->wake_pkt_total_len, ev->wake_pkt_data_len, ev->wake_pkt_control_flags,
	    ev->wake_pkt_owner_pname, ev->wake_pkt_effective_pname,
	    ev->wake_pkt_flags & NPIF_CONNECTION_IDLE ? 1 : 0,
	    ev->wake_pkt_flags & NPIF_LPW ? 1 : 0);
}

#endif /* (DEBUG || DEVELOPMENT) */

/*
 * The process attribution of a wake packet can take several steps:
 *
 * 1) After device wakes, the first interface that sees a wake packet is the
 *    physical interface and we remember it via if_set_wake_physical_interface()
 *
 * 2) We try to attribute a packet to a flow or not based on the physical interface.
 *    If we find a flow, then the physical interface is the same as the interface used
 *    by the TCP/UDP flow.
 *
 * 3) If the packet is tunneled or redirected we are going to do the attribution again
 *    and the physical will be different from the interface used the TCP/UDP flow.
 */
static bool
is_wake_pkt_event_delay(uint32_t ifrtype)
{
	// Prevent overflow of the bitstring
	if (ifrtype >= NPI_MAX_IF_FAMILY_BITS) {
		return false;
	}
	if (bitstr_test((bitstr_t *)&npi_wake_packet_event_delay_if_families, ifrtype)) {
		return true;
	}
	return false;
}

static int
if_set_wake_physical_interface(struct ifnet *ifp)
{
	/*
	 * A physical interface is either Ethernet, cellular or companion link over BT
	 * otherwise assumes it is some kind of tunnel
	 */
	if (ifp->if_family != IFNET_FAMILY_ETHERNET && ifp->if_family != IFNET_FAMILY_CELLULAR &&
	    IFNET_IS_COMPANION_LINK_BLUETOOTH(ifp) == false) {
		if (if_ports_used_verbose > 1) {
			os_log(wake_packet_log_handle, "if_set_wake_physical_interface %s ignored",
			    IF_XNAME(ifp));
		}
		return 0;
	}

	/* In LPW is is expected to get several wakes so do not suppress successive ones */
	if (if_is_lpw_enabled(ifp) == false) {
		/*
		 * Only handle a wake from a physical interface per wake cycle
		 */
		if (last_wake_phy_if_set == true) {
			if_ports_used_stats.ifpu_wake_pkt_event_error += 1;
			if (if_ports_used_verbose > 0) {
				os_log(wake_packet_log_handle,
				    "if_set_wake_physical_interface ignored on %s because already set on %s",
				    IF_XNAME(ifp), last_wake_phy_if_name);
			}
			return EJUSTRETURN;
		}

		last_wake_phy_if_set = true;

		if (if_need_delayed_wake_pkt_event(ifp)) {
			if_ports_used_stats.ifpu_delay_phy_wake_pkt += 1;
			last_wake_phy_if_delay_wake_pkt = true;
			if (if_ports_used_verbose > 0) {
				os_log(wake_packet_log_handle, "if_set_wake_physical_interface %s last_wake_phy_if_delay_wake_pkt set",
				    IF_XNAME(ifp));
			}
		}
	}

	if (ifp->if_delegated.ifp != NULL) {
		struct ifnet *delegated_ifp = ifp->if_delegated.ifp;

		strlcpy(last_wake_phy_if_name, IF_XNAME(delegated_ifp), sizeof(last_wake_phy_if_name));
		last_wake_phy_if_family = delegated_ifp->if_family;
		last_wake_phy_if_subfamily = delegated_ifp->if_subfamily;
		last_wake_phy_if_functional_type = if_functional_type(delegated_ifp, true);
		if (if_ports_used_verbose > 0) {
			os_log(wake_packet_log_handle,
			    "if_set_wake_physical_interface %s delegate of %s",
			    IF_XNAME(delegated_ifp), IF_XNAME(ifp));
		}
	} else {
		strlcpy(last_wake_phy_if_name, IF_XNAME(ifp), sizeof(last_wake_phy_if_name));
		last_wake_phy_if_family = ifp->if_family;
		last_wake_phy_if_subfamily = ifp->if_subfamily;
		last_wake_phy_if_functional_type = if_functional_type(ifp, true);
		if (if_ports_used_verbose > 0) {
			os_log(wake_packet_log_handle,
			    "if_set_wake_physical_interface %s",
			    IF_XNAME(ifp));
		}
	}

	if ((ifp->if_flags & IFXF_LOW_POWER_WAKE) != 0) {
		last_wake_phy_if_lpw = true;
	}

	return 0;
}

static void
deliver_unattributed_wake_packet_event(struct net_port_info_una_wake_event *event_data)
{
	struct kev_msg ev_msg = {};

	if_ports_used_stats.ifpu_unattributed_wake_event += 1;

	last_wake_pkt_event.npi_wp_code = KEV_POWER_UNATTRIBUTED_WAKE;
	memcpy(&last_wake_pkt_event.npi_ev_wake_pkt_unattributed, event_data,
	    sizeof(struct net_port_info_una_wake_event));

	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_POWER_SUBCLASS;
	ev_msg.event_code  = KEV_POWER_UNATTRIBUTED_WAKE;

	ev_msg.dv[0].data_ptr = event_data;
	ev_msg.dv[0].data_length = sizeof(struct net_port_info_una_wake_event);

	int result = kev_post_msg(&ev_msg);
	if (result != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data->una_wake_uuid, wake_uuid_str);
		os_log_error(wake_packet_log_handle,
		    "%s: kev_post_msg() failed with error %d for wake uuid %s",
		    __func__, result, wake_uuid_str);

		if_ports_used_stats.ifpu_wake_pkt_event_error += 1;
	}
#if (DEBUG || DEVELOPMENT)
	net_port_info_log_una_wake_event("unattributed wake packet event", event_data);
#endif /* (DEBUG || DEVELOPMENT) */
}

static void
deliver_attributed_wake_packet_event(struct net_port_info_wake_event *event_data)
{
	struct kev_msg ev_msg = {};

	has_notified_wake_pkt = true;

	if_ports_used_stats.ifpu_wake_pkt_event += 1;

	last_wake_pkt_event.npi_wp_code = KEV_POWER_WAKE_PACKET;
	memcpy(&last_wake_pkt_event.npi_ev_wake_pkt_attributed, event_data,
	    sizeof(struct net_port_info_wake_event));

	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_POWER_SUBCLASS;
	ev_msg.event_code  = KEV_POWER_WAKE_PACKET;

	ev_msg.dv[0].data_ptr = event_data;
	ev_msg.dv[0].data_length = sizeof(struct net_port_info_wake_event);

	int result = kev_post_msg(&ev_msg);
	if (result != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data->wake_uuid, wake_uuid_str);
		os_log_error(wake_packet_log_handle,
		    "%s: kev_post_msg() failed with error %d for wake uuid %s",
		    __func__, result, wake_uuid_str);

		if_ports_used_stats.ifpu_wake_pkt_event_error += 1;
	}
#if (DEBUG || DEVELOPMENT)
	net_port_info_log_wake_event("attributed wake packet event", event_data);
#endif /* (DEBUG || DEVELOPMENT) */
}

static bool
is_unattributed_wake_already_notified(struct net_port_info *npi)
{
	bool retval = false;

	if (has_notified_unattributed_wake == true || has_notified_wake_pkt == true) {
		if_ports_used_stats.ifpu_dup_unattributed_wake_event += 1;

		if (__improbable(net_wake_pkt_debug > 0)) {
			net_port_info_log_npi("already notified unattributed wake packet", npi);
		}
		retval = true;
	}

	return retval;
}

static void
check_for_existing_delayed_wake_event()
{
	/*
	 * Count the delayed events that are ignored as the most recent delayed
	 * wake event wins as the packet makes up its way up the stack
	 */
	if (delay_wake_pkt_event.npi_wp_code == KEV_POWER_WAKE_PACKET) {
		if_ports_used_stats.ifpu_ignored_delayed_attributed_events += 1;
	} else if (delay_wake_pkt_event.npi_wp_code == KEV_POWER_UNATTRIBUTED_WAKE) {
		if_ports_used_stats.ifpu_ignored_delayed_unattributed_events += 1;
	}
}

static void
if_notify_unattributed_wake_common(struct ifnet *ifp, struct net_port_info *npi,
    struct net_port_info_una_wake_event *event_data)
{
	LCK_RW_ASSERT(&net_port_entry_head_lock, LCK_RW_ASSERT_NOT_OWNED);
	lck_rw_lock_exclusive(&net_port_entry_head_lock);

	if (is_unattributed_wake_already_notified(npi) == true) {
		goto done;
	}

	/*
	 * Check if this is a wake packet that we cannot process inline
	 */
	if (if_need_delayed_wake_pkt_event(ifp)) {
		check_for_existing_delayed_wake_event();

		delay_wake_pkt_event.npi_wp_code = KEV_POWER_UNATTRIBUTED_WAKE;
		memcpy(&delay_wake_pkt_event.npi_ev_wake_pkt_unattributed, event_data,
		    sizeof(struct net_port_info_una_wake_event));

#if (DEBUG || DEVELOPMENT)
		if (if_ports_used_verbose > 0) {
			net_port_info_log_una_wake_event("delay unattributed wake packet event", event_data);
		}
#endif /* (DEBUG || DEVELOPMENT) */

		goto done;
	}
	deliver_unattributed_wake_packet_event(event_data);

done:
	lck_rw_unlock_exclusive(&net_port_entry_head_lock);
}

static void
if_notify_unattributed_wake_mbuf(struct ifnet *ifp, struct mbuf *m,
    struct net_port_info *npi, uint32_t pkt_total_len, uint32_t pkt_data_len,
    uint16_t pkt_control_flags, uint16_t proto)
{
	struct net_port_info_una_wake_event event_data = {};

	uuid_copy(event_data.una_wake_uuid, current_wakeuuid);
	event_data.una_wake_pkt_if_index = ifp->if_index;
	event_data.una_wake_pkt_flags = npi->npi_flags;

	event_data.una_wake_pkt_local_port = npi->npi_local_port;
	event_data.una_wake_pkt_foreign_port = npi->npi_foreign_port;
	event_data.una_wake_pkt_local_addr_ = npi->npi_local_addr_;
	event_data.una_wake_pkt_foreign_addr_ = npi->npi_foreign_addr_;

	event_data.una_wake_pkt_total_len = pkt_total_len;
	event_data.una_wake_pkt_data_len = pkt_data_len;
	event_data.una_wake_pkt_control_flags = pkt_control_flags;
	event_data.una_wake_pkt_proto = proto;

	strlcpy(event_data.una_wake_pkt_ifname, IF_XNAME(ifp),
	    sizeof(event_data.una_wake_pkt_ifname));
	event_data.una_wake_pkt_if_info.npi_if_family = ifp->if_family;
	event_data.una_wake_pkt_if_info.npi_if_subfamily = ifp->if_subfamily;
	event_data.una_wake_pkt_if_info.npi_if_functional_type = if_functional_type(ifp, true);

	strbufcpy(event_data.una_wake_pkt_phy_ifname, last_wake_phy_if_name);
	event_data.una_wake_pkt_phy_if_info.npi_if_family = last_wake_phy_if_family;
	event_data.una_wake_pkt_phy_if_info.npi_if_subfamily = last_wake_phy_if_subfamily;
	event_data.una_wake_pkt_phy_if_info.npi_if_functional_type = last_wake_phy_if_functional_type;

	event_data.una_wake_ptk_len = m->m_pkthdr.len > NPI_MAX_UNA_WAKE_PKT_LEN ?
	    NPI_MAX_UNA_WAKE_PKT_LEN : (u_int16_t)m->m_pkthdr.len;

	errno_t error = mbuf_copydata(m, 0, event_data.una_wake_ptk_len,
	    (void *)event_data.una_wake_pkt);
	if (error != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data.una_wake_uuid, wake_uuid_str);
		os_log_error(wake_packet_log_handle,
		    "%s: mbuf_copydata() failed with error %d for wake uuid %s",
		    __func__, error, wake_uuid_str);

		if_ports_used_stats.ifpu_unattributed_wake_event_error += 1;
		return;
	}

	strlcpy(event_data.una_wake_pkt_ifname, IF_XNAME(ifp),
	    sizeof(event_data.una_wake_pkt_ifname));
	event_data.una_wake_pkt_if_info.npi_if_family = ifp->if_family;
	event_data.una_wake_pkt_if_info.npi_if_subfamily = ifp->if_subfamily;
	event_data.una_wake_pkt_if_info.npi_if_functional_type = if_functional_type(ifp, true);

	strbufcpy(event_data.una_wake_pkt_phy_ifname, last_wake_phy_if_name);
	event_data.una_wake_pkt_phy_if_info.npi_if_family = last_wake_phy_if_family;
	event_data.una_wake_pkt_phy_if_info.npi_if_subfamily = last_wake_phy_if_subfamily;
	event_data.una_wake_pkt_phy_if_info.npi_if_functional_type = last_wake_phy_if_functional_type;

	if_notify_unattributed_wake_common(ifp, npi, &event_data);
}

static bool
is_attributed_wake_already_notified(struct net_port_info *npi)
{
	if (has_notified_wake_pkt == true) {
		if_ports_used_stats.ifpu_dup_wake_pkt_event += 1;
		if (__improbable(net_wake_pkt_debug > 0)) {
			net_port_info_log_npi("already notified attributed wake packet", npi);
		}
		return true;
	}

	return false;
}

static void
if_notify_wake_packet(struct ifnet *ifp, struct net_port_info *npi,
    uint32_t pkt_total_len, uint32_t pkt_data_len, uint16_t pkt_control_flags)
{
	struct net_port_info_wake_event event_data = {};

	uuid_copy(event_data.wake_uuid, current_wakeuuid);
	event_data.wake_pkt_if_index = ifp->if_index;
	event_data.wake_pkt_port = npi->npi_local_port;
	event_data.wake_pkt_flags = npi->npi_flags;
	event_data.wake_pkt_owner_pid = npi->npi_owner_pid;
	event_data.wake_pkt_effective_pid = npi->npi_effective_pid;
	strbufcpy(event_data.wake_pkt_owner_pname, npi->npi_owner_pname);
	strbufcpy(event_data.wake_pkt_effective_pname, npi->npi_effective_pname);
	uuid_copy(event_data.wake_pkt_owner_uuid, npi->npi_owner_uuid);
	uuid_copy(event_data.wake_pkt_effective_uuid, npi->npi_effective_uuid);

	event_data.wake_pkt_foreign_port = npi->npi_foreign_port;
	event_data.wake_pkt_local_addr_ = npi->npi_local_addr_;
	event_data.wake_pkt_foreign_addr_ = npi->npi_foreign_addr_;
	strlcpy(event_data.wake_pkt_ifname, IF_XNAME(ifp), sizeof(event_data.wake_pkt_ifname));

	event_data.wake_pkt_if_info.npi_if_family = ifp->if_family;
	event_data.wake_pkt_if_info.npi_if_subfamily = ifp->if_subfamily;
	event_data.wake_pkt_if_info.npi_if_functional_type = if_functional_type(ifp, true);

	strbufcpy(event_data.wake_pkt_phy_ifname, last_wake_phy_if_name);
	event_data.wake_pkt_phy_if_info.npi_if_family = last_wake_phy_if_family;
	event_data.wake_pkt_phy_if_info.npi_if_subfamily = last_wake_phy_if_subfamily;
	event_data.wake_pkt_phy_if_info.npi_if_functional_type = last_wake_phy_if_functional_type;

	event_data.wake_pkt_total_len = pkt_total_len;
	event_data.wake_pkt_data_len = pkt_data_len;
	event_data.wake_pkt_control_flags = pkt_control_flags;
	if (npi->npi_flags & NPIF_NOWAKE) {
		event_data.wake_pkt_control_flags |= NPICF_NOWAKE;
	}

	LCK_RW_ASSERT(&net_port_entry_head_lock, LCK_RW_ASSERT_NOT_OWNED);

	lck_rw_lock_exclusive(&net_port_entry_head_lock);

	/*
	 * Always immediately notify attributed wake for idle connections in LPW
	 * even if an attributed wake has already been notified or
	 * the interface requires delayed wake attribution
	 */
	if (if_is_lpw_enabled(ifp) &&
	    (npi->npi_flags & NPIF_CONNECTION_IDLE) != 0) {
		goto deliver;
	}

	if (is_attributed_wake_already_notified(npi) == true) {
		goto done;
	}

	/*
	 * Check if this is a wake packet that we cannot process inline
	 * We do not delay attributed idle connections in LPW because it is more
	 * important to get accurate count about attributed idle connections in LPW
	 * than an accurate count of attributed wake.
	 */
	if (if_need_delayed_wake_pkt_event(ifp)) {
		check_for_existing_delayed_wake_event();

		delay_wake_pkt_event.npi_wp_code = KEV_POWER_WAKE_PACKET;
		memcpy(&delay_wake_pkt_event.npi_ev_wake_pkt_attributed, &event_data,
		    sizeof(struct net_port_info_wake_event));

#if (DEBUG || DEVELOPMENT)
		if (if_ports_used_verbose > 0) {
			net_port_info_log_wake_event("delay attributed wake packet event", &event_data);
		}
#endif /* (DEBUG || DEVELOPMENT) */

		goto done;
	}

deliver:
	if (npi->npi_flags & NPIF_NOWAKE) {
		if_ports_used_stats.ifpu_spurious_wake_event += 1;
	}

	deliver_attributed_wake_packet_event(&event_data);
done:
	lck_rw_unlock_exclusive(&net_port_entry_head_lock);
}

static bool
is_encapsulated_esp(struct mbuf *m, size_t data_offset)
{
	/*
	 * They are three cases:
	 * - Keep alive: 1 byte payload
	 * - IKE: payload start with 4 bytes header set to zero before ISAKMP header
	 * - otherwise it's ESP
	 */
	ASSERT(m->m_pkthdr.len >= data_offset);

	size_t data_len = m->m_pkthdr.len - data_offset;
	if (data_len == 1) {
		return false;
	} else if (data_len > ESP_HDR_SIZE) {
		uint8_t payload[ESP_HDR_SIZE];

		errno_t error = mbuf_copydata(m, data_offset, ESP_HDR_SIZE, &payload);
		if (error != 0) {
			os_log(wake_packet_log_handle, "%s: mbuf_copydata(ESP_HDR_SIZE) error %d",
			    __func__, error);
		} else if (payload[0] == 0 && payload[1] == 0 &&
		    payload[2] == 0 && payload[3] == 0) {
			return false;
		}
	}
	return true;
}

extern void log_hexdump(os_log_t log_handle, void *__sized_by(len) data, size_t len);

void
log_hexdump(os_log_t log_handle, void *__sized_by(len) data, size_t len)
{
	size_t i, j, k;
	unsigned char *ptr = (unsigned char *)data;
#define MAX_DUMP_BUF 32
	unsigned char buf[3 * MAX_DUMP_BUF + 1];

	for (i = 0; i < len; i += MAX_DUMP_BUF) {
		for (j = i, k = 0; j < i + MAX_DUMP_BUF && j < len; j++) {
			unsigned char msnbl = ptr[j] >> 4;
			unsigned char lsnbl = ptr[j] & 0x0f;

			buf[k++] = msnbl < 10 ? msnbl + '0' : msnbl + 'a' - 10;
			buf[k++] = lsnbl < 10 ? lsnbl + '0' : lsnbl + 'a' - 10;

			if ((j % 2) == 1) {
				buf[k++] = ' ';
			}
			if ((j % MAX_DUMP_BUF) == MAX_DUMP_BUF - 1) {
				buf[k++] = ' ';
			}
		}
		buf[k] = 0;
		os_log(log_handle, "%3lu: %s", i, buf);
	}
}

static void
log_wake_mbuf(struct ifnet *ifp, struct mbuf *m)
{
	char buffer[64];
	size_t buflen = MIN(mbuf_pkthdr_len(m), sizeof(buffer));

	os_log(wake_packet_log_handle, "wake packet from %s len %d",
	    ifp->if_xname, m_pktlen(m));
	if (mbuf_copydata(m, 0, buflen, buffer) == 0) {
		log_hexdump(wake_packet_log_handle, buffer, buflen);
	}
}

__attribute__((noinline))
void
if_ports_used_match_mbuf(struct ifnet *ifp, protocol_family_t proto_family, struct mbuf *m)
{
	errno_t error;
	struct net_port_info npi = {};
	bool found = false;
	uint32_t pkt_total_len = 0;
	uint32_t pkt_data_len = 0;
	uint16_t pkt_control_flags = 0;
	uint16_t pkt_proto = 0;
	uint32_t gencnt = 0;

	if (ifp == NULL) {
		os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: receive interface is NULL");
		if_ports_used_stats.ifpu_unattributed_null_recvif += 1;
		return;
	}

	if ((m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT) == 0 && if_is_lpw_enabled(ifp) == false) {
		return;
	}

	if (__improbable(net_wake_pkt_debug > 0)) {
		log_wake_mbuf(ifp, m);
	}

	/*
	 * Packet received in LPW mode have a special handling as they are
	 * not necessarily marked as wake packets
	 */
	if (if_is_lpw_enabled(ifp) == false) {
		if ((m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT) == 0) {
			if_ports_used_stats.ifpu_match_wake_pkt_no_flag += 1;
			os_log_error(wake_packet_log_handle, "if_ports_used_match_mbuf: called PKTF_WAKE_PKT not set from %s",
			    IF_XNAME(ifp));
			return;
		}
	}
	/*
	 * Only accept one wake packet from a physical interface per wake cycle as we
	 * can get spurious wake packets from some interfaces
	 */
	if (if_set_wake_physical_interface(ifp) == EJUSTRETURN) {
		m->m_pkthdr.pkt_flags &= ~PKTF_WAKE_PKT;
		return;
	}

	if_ports_used_stats.ifpu_so_match_wake_pkt += 1;
	npi.npi_flags |= NPIF_SOCKET; /* For logging */
	pkt_total_len = m->m_pkthdr.len;
	pkt_data_len = pkt_total_len;

	npi.npi_if_index = ifp->if_index;
	if (IFNET_IS_COMPANION_LINK(ifp)) {
		npi.npi_flags |= NPIF_COMPLINK;
	}

	if (proto_family == PF_INET) {
		struct ip iphdr = {};

		if_ports_used_stats.ifpu_ipv4_wake_pkt += 1;

		error = mbuf_copydata(m, 0, sizeof(struct ip), &iphdr);
		if (error != 0) {
			os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(ip) error %d",
			    error);
			goto failed;
		}
		npi.npi_flags |= NPIF_IPV4;
		npi.npi_local_addr_in = iphdr.ip_dst;
		npi.npi_foreign_addr_in = iphdr.ip_src;

		/*
		 * Check if this is a fragment that is not the first fragment
		 */
		if ((ntohs(iphdr.ip_off) & ~(IP_DF | IP_RF)) &&
		    (ntohs(iphdr.ip_off) & IP_OFFMASK) != 0) {
			npi.npi_flags |= NPIF_FRAG;
			if_ports_used_stats.ifpu_frag_wake_pkt += 1;
		}

		if ((iphdr.ip_hl << 2) < pkt_data_len) {
			pkt_data_len -= iphdr.ip_hl << 2;
		} else {
			pkt_data_len = 0;
		}

		pkt_proto = iphdr.ip_p;

		switch (iphdr.ip_p) {
		case IPPROTO_TCP: {
			if_ports_used_stats.ifpu_tcp_wake_pkt += 1;
			npi.npi_flags |= NPIF_TCP;

			if (npi.npi_flags & NPIF_FRAG) {
				goto failed;
			}

			struct tcphdr th = {};
			error = mbuf_copydata(m, iphdr.ip_hl << 2, sizeof(struct tcphdr), &th);
			if (error != 0) {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(tcphdr) error %d",
				    error);
				goto failed;
			}
			npi.npi_local_port = th.th_dport;
			npi.npi_foreign_port = th.th_sport;

			if (pkt_data_len < sizeof(struct tcphdr) ||
			    pkt_data_len < (th.th_off << 2)) {
				pkt_data_len = 0;
			} else {
				pkt_data_len -= th.th_off << 2;
			}
			pkt_control_flags = th.th_flags;
			break;
		}
		case IPPROTO_UDP: {
			if_ports_used_stats.ifpu_udp_wake_pkt += 1;
			npi.npi_flags |= NPIF_UDP;

			if (npi.npi_flags & NPIF_FRAG) {
				goto failed;
			}
			struct udphdr uh = {};
			size_t udp_offset = iphdr.ip_hl << 2;

			error = mbuf_copydata(m, udp_offset, sizeof(struct udphdr), &uh);
			if (error != 0) {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(udphdr) error %d",
				    error);
				goto failed;
			}
			npi.npi_local_port = uh.uh_dport;
			npi.npi_foreign_port = uh.uh_sport;
			/*
			 * Let the ESP layer handle wake packets
			 */
			if (ntohs(uh.uh_dport) == PORT_ISAKMP_NATT ||
			    ntohs(uh.uh_sport) == PORT_ISAKMP_NATT) {
				if_ports_used_stats.ifpu_isakmp_natt_wake_pkt += 1;
				if (is_encapsulated_esp(m, udp_offset + sizeof(struct udphdr))) {
					if (net_wake_pkt_debug > 0) {
						net_port_info_log_npi("defer ISAKMP_NATT matching", &npi);
					}
					return;
				}
			}

			if (pkt_data_len < sizeof(struct udphdr)) {
				pkt_data_len = 0;
			} else {
				pkt_data_len -= sizeof(struct udphdr);
			}
			break;
		}
		case IPPROTO_ESP: {
			/*
			 * Let the ESP layer handle wake packets
			 */
			if_ports_used_stats.ifpu_esp_wake_pkt += 1;
			npi.npi_flags |= NPIF_ESP;
			if (net_wake_pkt_debug > 0) {
				net_port_info_log_npi("defer ESP matching", &npi);
			}
			return;
		}
		default:
			if_ports_used_stats.ifpu_bad_proto_wake_pkt += 1;
			os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: unexpected IPv4 protocol %u from %s",
			    iphdr.ip_p, IF_XNAME(ifp));
			goto failed;
		}
	} else if (proto_family == PF_INET6) {
		struct ip6_hdr ip6_hdr = {};

		if_ports_used_stats.ifpu_ipv6_wake_pkt += 1;

		error = mbuf_copydata(m, 0, sizeof(struct ip6_hdr), &ip6_hdr);
		if (error != 0) {
			os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(ip6_hdr) error %d",
			    error);
			goto failed;
		}
		npi.npi_flags |= NPIF_IPV6;
		memcpy(&npi.npi_local_addr_in6, &ip6_hdr.ip6_dst, sizeof(struct in6_addr));
		memcpy(&npi.npi_foreign_addr_in6, &ip6_hdr.ip6_src, sizeof(struct in6_addr));

		size_t l3_len = sizeof(struct ip6_hdr);
		uint8_t l4_proto = ip6_hdr.ip6_nxt;

		pkt_proto = l4_proto;

		if (pkt_data_len < l3_len) {
			pkt_data_len = 0;
		} else {
			pkt_data_len -= l3_len;
		}

		/*
		 * Check if this is a fragment that is not the first fragment
		 */
		if (l4_proto == IPPROTO_FRAGMENT) {
			struct ip6_frag ip6_frag;

			error = mbuf_copydata(m, sizeof(struct ip6_hdr), sizeof(struct ip6_frag), &ip6_frag);
			if (error != 0) {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(ip6_frag) error %d",
				    error);
				goto failed;
			}

			l3_len += sizeof(struct ip6_frag);
			l4_proto = ip6_frag.ip6f_nxt;

			if ((ip6_frag.ip6f_offlg & IP6F_OFF_MASK) != 0) {
				npi.npi_flags |= NPIF_FRAG;
				if_ports_used_stats.ifpu_frag_wake_pkt += 1;
			}
		}


		switch (l4_proto) {
		case IPPROTO_TCP: {
			if_ports_used_stats.ifpu_tcp_wake_pkt += 1;
			npi.npi_flags |= NPIF_TCP;

			/*
			 * Cannot attribute a fragment that is not the first fragment as it
			 * not have the TCP header
			 */
			if (npi.npi_flags & NPIF_FRAG) {
				goto failed;
			}

			struct tcphdr th = {};

			error = mbuf_copydata(m, l3_len, sizeof(struct tcphdr), &th);
			if (error != 0) {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(tcphdr) error %d",
				    error);
				if_ports_used_stats.ifpu_incomplete_tcp_hdr_pkt += 1;
				goto failed;
			}
			npi.npi_local_port = th.th_dport;
			npi.npi_foreign_port = th.th_sport;

			if (pkt_data_len < sizeof(struct tcphdr) ||
			    pkt_data_len < (th.th_off << 2)) {
				pkt_data_len = 0;
			} else {
				pkt_data_len -= th.th_off << 2;
			}
			pkt_control_flags = th.th_flags;
			break;
		}
		case IPPROTO_UDP: {
			if_ports_used_stats.ifpu_udp_wake_pkt += 1;
			npi.npi_flags |= NPIF_UDP;

			/*
			 * Cannot attribute a fragment that is not the first fragment as it
			 * not have the UDP header
			 */
			if (npi.npi_flags & NPIF_FRAG) {
				goto failed;
			}

			struct udphdr uh = {};

			error = mbuf_copydata(m, l3_len, sizeof(struct udphdr), &uh);
			if (error != 0) {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: mbuf_copydata(udphdr) error %d",
				    error);
				if_ports_used_stats.ifpu_incomplete_udp_hdr_pkt += 1;
				goto failed;
			}
			npi.npi_local_port = uh.uh_dport;
			npi.npi_foreign_port = uh.uh_sport;
			/*
			 * Let the ESP layer handle wake packets
			 */
			if (ntohs(npi.npi_local_port) == PORT_ISAKMP_NATT ||
			    ntohs(npi.npi_foreign_port) == PORT_ISAKMP_NATT) {
				if_ports_used_stats.ifpu_isakmp_natt_wake_pkt += 1;
				if (is_encapsulated_esp(m, l3_len + sizeof(struct udphdr))) {
					if (net_wake_pkt_debug > 0) {
						net_port_info_log_npi("defer encapsulated ESP matching", &npi);
					}
					return;
				}
			}

			if (pkt_data_len < sizeof(struct udphdr)) {
				pkt_data_len = 0;
			} else {
				pkt_data_len -= sizeof(struct udphdr);
			}
			break;
		}
		case IPPROTO_ESP: {
			/*
			 * Let the ESP layer handle the wake packet
			 */
			if_ports_used_stats.ifpu_esp_wake_pkt += 1;
			npi.npi_flags |= NPIF_ESP;
			if (net_wake_pkt_debug > 0) {
				net_port_info_log_npi("defer ESP matching", &npi);
			}
			return;
		}
		default:
			if_ports_used_stats.ifpu_bad_proto_wake_pkt += 1;

			os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: unexpected IPv6 protocol %u from %s",
			    ip6_hdr.ip6_nxt, IF_XNAME(ifp));
			goto failed;
		}
	} else {
		if_ports_used_stats.ifpu_bad_family_wake_pkt += 1;
		os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: unexpected protocol family %d from %s",
		    proto_family, IF_XNAME(ifp));
		goto failed;
	}

	found = net_port_info_find_match(ifp, &npi, &gencnt);

failed:
	/*
	 * Because of LPW, we can receive a train of packet for an idle connection
	 * in the same wake cycle so use a generation count to prevent the generation
	 * of duplicate attribute wake packet event. This cover both LPW and non-LPW modes.
	 *
	 * Unattributed wake packet events have a zero gencnt
	 */
	if (gencnt != wake_attribution_gencnt) {
		if ((m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT) != 0) {
			npi.npi_flags |= NPIF_WAKEPKT;
		}

		if (if_is_lpw_enabled(ifp) == true) {
			npi.npi_flags |= NPIF_LPW;

			if (found && (npi.npi_flags & NPIF_CONNECTION_IDLE)) {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: idle connection in LPW on %s",
				    IF_XNAME(ifp));

				if_ports_used_stats.ifpu_lpw_connection_idle_wake++;
			} else {
				os_log(wake_packet_log_handle, "if_ports_used_match_mbuf: not idle connection in LPW on %s",
				    IF_XNAME(ifp));

				if_ports_used_stats.ifpu_lpw_not_idle_wake++;
			}
		}

		if (found) {
			if_notify_wake_packet(ifp, &npi,
			    pkt_total_len, pkt_data_len, pkt_control_flags);
		} else {
			if_notify_unattributed_wake_mbuf(ifp, m, &npi,
			    pkt_total_len, pkt_data_len, pkt_control_flags, pkt_proto);
		}
	}
}

#if SKYWALK

static void
if_notify_unattributed_wake_pkt(struct ifnet *ifp, struct __kern_packet *pkt,
    struct net_port_info *npi, uint32_t pkt_total_len, uint32_t pkt_data_len,
    uint16_t pkt_control_flags, uint16_t proto)
{
	struct net_port_info_una_wake_event event_data = {};

	uuid_copy(event_data.una_wake_uuid, current_wakeuuid);
	event_data.una_wake_pkt_if_index = ifp->if_index;
	event_data.una_wake_pkt_flags = npi->npi_flags;

	uint16_t offset = kern_packet_get_network_header_offset(SK_PKT2PH(pkt));
	event_data.una_wake_ptk_len =
	    pkt->pkt_length - offset > NPI_MAX_UNA_WAKE_PKT_LEN ?
	    NPI_MAX_UNA_WAKE_PKT_LEN : (u_int16_t) pkt->pkt_length - offset;

	kern_packet_copy_bytes(SK_PKT2PH(pkt), offset, event_data.una_wake_ptk_len,
	    event_data.una_wake_pkt);

	event_data.una_wake_pkt_local_port = npi->npi_local_port;
	event_data.una_wake_pkt_foreign_port = npi->npi_foreign_port;
	event_data.una_wake_pkt_local_addr_ = npi->npi_local_addr_;
	event_data.una_wake_pkt_foreign_addr_ = npi->npi_foreign_addr_;
	strlcpy(event_data.una_wake_pkt_ifname, IF_XNAME(ifp),
	    sizeof(event_data.una_wake_pkt_ifname));

	event_data.una_wake_pkt_total_len = pkt_total_len;
	event_data.una_wake_pkt_data_len = pkt_data_len;
	event_data.una_wake_pkt_control_flags = pkt_control_flags;
	event_data.una_wake_pkt_proto = proto;

	if_notify_unattributed_wake_common(ifp, npi, &event_data);
}

static void
log_wake_pkt(struct ifnet *ifp, struct __kern_packet *pkt)
{
	uint32_t len;

	if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
		len = m_pktlen(pkt->pkt_mbuf);
	} else {
		len = __packet_get_real_data_length(pkt);
	}

	os_log(wake_packet_log_handle, "wake packet from %s len %d",
	    ifp->if_xname, len);
}

__attribute__((noinline))
void
if_ports_used_match_pkt(struct ifnet *ifp, struct __kern_packet *pkt)
{
	struct net_port_info npi = {};
	bool found = false;
	uint32_t pkt_total_len = 0;
	uint32_t pkt_data_len = 0;
	uint16_t pkt_control_flags = 0;
	uint16_t pkt_proto = 0;
	uint32_t gencnt = 0; /* Wake generation count for the entry is not zero if found */

	if (ifp == NULL) {
		os_log(wake_packet_log_handle, "if_ports_used_match_pkt: receive interface is NULL");
		if_ports_used_stats.ifpu_unattributed_null_recvif += 1;
		return;
	}

	if ((pkt->pkt_pflags & PKT_F_WAKE_PKT) == 0 && if_is_lpw_enabled(ifp) == false) {
		return;
	}

	if (__improbable(net_wake_pkt_debug > 0)) {
		log_wake_pkt(ifp, pkt);
	}

	/*
	 * Packet received in LPW mode have a special handling as they are
	 * not necessarily wake packets
	 */
	if (if_is_lpw_enabled(ifp) == false) {
		if ((pkt->pkt_pflags & PKT_F_WAKE_PKT) == 0) {
			if_ports_used_stats.ifpu_match_wake_pkt_no_flag += 1;
			os_log_error(wake_packet_log_handle, "%s: called PKT_F_WAKE_PKT not set from %s",
			    __func__, IF_XNAME(ifp));
			return;
		}
	}
	/*
	 * Only accept one wake packet from a physical interface per wake cycle as we
	 * can get spurious wake packets from some interfaces
	 */
	if (if_set_wake_physical_interface(ifp) == EJUSTRETURN) {
		pkt->pkt_pflags &= ~PKT_F_WAKE_PKT;
		return;
	}

	if_ports_used_stats.ifpu_ch_match_wake_pkt += 1;
	npi.npi_flags |= NPIF_CHANNEL; /* For logging */
	pkt_total_len = pkt->pkt_flow_ip_hlen +
	    pkt->pkt_flow_tcp_hlen + pkt->pkt_flow_ulen;
	pkt_data_len = pkt->pkt_flow_ulen;

	npi.npi_if_index = ifp->if_index;
	if (IFNET_IS_COMPANION_LINK(ifp)) {
		npi.npi_flags |= NPIF_COMPLINK;
	}


	switch (pkt->pkt_flow_ip_ver) {
	case IPVERSION:
		if_ports_used_stats.ifpu_ipv4_wake_pkt += 1;

		npi.npi_flags |= NPIF_IPV4;
		npi.npi_local_addr_in = pkt->pkt_flow_ipv4_dst;
		npi.npi_foreign_addr_in = pkt->pkt_flow_ipv4_src;
		break;
	case IPV6_VERSION:
		if_ports_used_stats.ifpu_ipv6_wake_pkt += 1;

		npi.npi_flags |= NPIF_IPV6;
		memcpy(&npi.npi_local_addr_in6, &pkt->pkt_flow_ipv6_dst,
		    sizeof(struct in6_addr));
		memcpy(&npi.npi_foreign_addr_in6, &pkt->pkt_flow_ipv6_src,
		    sizeof(struct in6_addr));
		break;
	default:
		if_ports_used_stats.ifpu_bad_family_wake_pkt += 1;

		os_log(wake_packet_log_handle, "%s: unexpected protocol family %u from %s",
		    __func__, pkt->pkt_flow_ip_ver, IF_XNAME(ifp));
		goto failed;
	}
	pkt_proto = pkt->pkt_flow_ip_ver;

	/*
	 * Check if this is a fragment that is not the first fragment
	 */
	if (pkt->pkt_flow_ip_is_frag && !pkt->pkt_flow_ip_is_first_frag) {
		os_log(wake_packet_log_handle, "%s: unexpected wake fragment from %s",
		    __func__, IF_XNAME(ifp));
		npi.npi_flags |= NPIF_FRAG;
		if_ports_used_stats.ifpu_frag_wake_pkt += 1;
	}

	switch (pkt->pkt_flow_ip_proto) {
	case IPPROTO_TCP: {
		if_ports_used_stats.ifpu_tcp_wake_pkt += 1;
		npi.npi_flags |= NPIF_TCP;

		/*
		 * Cannot attribute a fragment that is not the first fragment as it
		 * not have the TCP header
		 */
		if (npi.npi_flags & NPIF_FRAG) {
			goto failed;
		}
		struct tcphdr * __single tcp = __unsafe_forge_single(struct tcphdr *, pkt->pkt_flow_tcp_hdr);
		if (tcp == NULL) {
			os_log(wake_packet_log_handle, "%s: pkt with unassigned TCP header from %s",
			    __func__, IF_XNAME(ifp));
			if_ports_used_stats.ifpu_incomplete_tcp_hdr_pkt += 1;
			goto failed;
		}
		npi.npi_local_port = tcp->th_dport;
		npi.npi_foreign_port = tcp->th_sport;
		pkt_control_flags = tcp->th_flags;
		break;
	}
	case IPPROTO_UDP: {
		if_ports_used_stats.ifpu_udp_wake_pkt += 1;
		npi.npi_flags |= NPIF_UDP;

		/*
		 * Cannot attribute a fragment that is not the first fragment as it
		 * not have the UDP header
		 */
		if (npi.npi_flags & NPIF_FRAG) {
			goto failed;
		}
		struct udphdr * __single uh = __unsafe_forge_single(struct udphdr *, pkt->pkt_flow_udp_hdr);
		if (uh == NULL) {
			os_log(wake_packet_log_handle, "%s: pkt with unassigned UDP header from %s",
			    __func__, IF_XNAME(ifp));
			if_ports_used_stats.ifpu_incomplete_udp_hdr_pkt += 1;
			goto failed;
		}
		npi.npi_local_port = uh->uh_dport;
		npi.npi_foreign_port = uh->uh_sport;

		/*
		 * Defer matching of UDP NAT traversal to ip_input
		 * (assumes IKE uses sockets)
		 */
		if (ntohs(npi.npi_local_port) == PORT_ISAKMP_NATT ||
		    ntohs(npi.npi_foreign_port) == PORT_ISAKMP_NATT) {
			if_ports_used_stats.ifpu_deferred_isakmp_natt_wake_pkt += 1;
			if (net_wake_pkt_debug > 0) {
				net_port_info_log_npi("defer ISAKMP_NATT matching", &npi);
			}
			return;
		}
		break;
	}
	case IPPROTO_ESP: {
		/*
		 * Let the ESP layer handle the wake packet
		 */
		if_ports_used_stats.ifpu_esp_wake_pkt += 1;
		npi.npi_flags |= NPIF_ESP;
		if (net_wake_pkt_debug > 0) {
			net_port_info_log_npi("defer ESP matching", &npi);
		}
		return;
	}
	default:
		if_ports_used_stats.ifpu_bad_proto_wake_pkt += 1;

		os_log(wake_packet_log_handle, "%s: unexpected IP protocol %u from %s",
		    __func__, pkt->pkt_flow_ip_proto, IF_XNAME(ifp));
		goto failed;
	}

	found = net_port_info_find_match(ifp, &npi, &gencnt);

failed:
	/*
	 * Because of LPW, we can receive a train of packet for an idle connection
	 * in the same wake cycle so use a generation count to prevent the generation
	 * of duplicate attribute wake packet event. This cover both LPW and non-LPW modes.
	 *
	 * Unattributed wake packet events have a zero gencnt
	 */
	if (gencnt != wake_attribution_gencnt) {
		if ((pkt->pkt_pflags & PKT_F_WAKE_PKT) != 0) {
			npi.npi_flags |= NPIF_WAKEPKT;
		}

		if (if_is_lpw_enabled(ifp) == true) {
			npi.npi_flags |= NPIF_LPW;

			if (found && (npi.npi_flags & NPIF_CONNECTION_IDLE)) {
				if (if_ports_used_verbose > 0) {
					os_log(wake_packet_log_handle, "if_ports_used_match_pkt: idle connection in LPW on %s",
					    IF_XNAME(ifp));
				}

				if_ports_used_stats.ifpu_lpw_connection_idle_wake++;
			} else {
				os_log(wake_packet_log_handle, "if_ports_used_match_pkt: not idle connection in LPW on %s",
				    IF_XNAME(ifp));

				if_ports_used_stats.ifpu_lpw_not_idle_wake++;
			}
		}

		if (found) {
			if_notify_wake_packet(ifp, &npi,
			    pkt_total_len, pkt_data_len, pkt_control_flags);
		} else {
			if_notify_unattributed_wake_pkt(ifp, pkt, &npi,
			    pkt_total_len, pkt_data_len, pkt_control_flags, pkt_proto);
		}
	}
}
#endif /* SKYWALK */

int
sysctl_last_attributed_wake_event SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct net_port_info_wake_event net_port_info_wake_event = { 0 };
	size_t len = sizeof(net_port_info_wake_event);
	int error;

	lck_rw_lock_shared(&net_port_entry_head_lock);
	if (last_wake_pkt_event.npi_wp_code == KEV_POWER_WAKE_PACKET) {
		memcpy(&net_port_info_wake_event, &last_wake_pkt_event.npi_ev_wake_pkt_attributed, len);
	}
	lck_rw_unlock_shared(&net_port_entry_head_lock);

	if (req->oldptr != 0) {
		len = MIN(req->oldlen, len);
	}
	error = SYSCTL_OUT(req, &net_port_info_wake_event, len);

	return error;
}

int
sysctl_last_unattributed_wake_event SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	struct net_port_info_una_wake_event net_port_info_una_wake_event = { 0 };
	size_t len = sizeof(net_port_info_una_wake_event);
	int error;

	lck_rw_lock_shared(&net_port_entry_head_lock);
	if (last_wake_pkt_event.npi_wp_code == KEV_POWER_UNATTRIBUTED_WAKE) {
		memcpy(&net_port_info_una_wake_event, &last_wake_pkt_event.npi_ev_wake_pkt_unattributed, len);
	}
	lck_rw_unlock_shared(&net_port_entry_head_lock);

	if (req->oldptr != 0) {
		len = MIN(req->oldlen, len);
	}
	error = SYSCTL_OUT(req, &net_port_info_una_wake_event, len);

	return error;
}

/*
 * Pass the interface family of the interface that caused the wake
 */
int
sysctl_wake_pkt_event_notify SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	long long val = 0;
	int error = 0;
	int changed = 0;
	uint32_t if_family = 0;

	error = sysctl_io_number(req, val, sizeof(val), &val, &changed);
	if (error != 0 || req->newptr == 0 || changed == 0) {
		return error;
	}

	if (val < 0 || val > UINT32_MAX) {
		return EINVAL;
	}
	if_family = (uint32_t)val;

	if (!IOCurrentTaskHasEntitlement(WAKE_PKT_EVENT_CONTROL_ENTITLEMENT)) {
		return EPERM;
	}

	os_log(wake_packet_log_handle, "sysctl_wake_pkt_event_notify proc %s:%u val %u last_wake_phy_if_delay_wake_pkt %d last_wake_phy_if_family %u delay_wake_pkt_event %d",
	    proc_best_name(current_proc()), proc_selfpid(),
	    if_family, last_wake_phy_if_delay_wake_pkt, last_wake_phy_if_family,
	    delay_wake_pkt_event.npi_wp_code);
#if (DEBUG || DEVELOPMENT)
	if (if_ports_used_verbose > 0) {
		if (delay_wake_pkt_event.npi_wp_code == KEV_POWER_WAKE_PACKET) {
			net_port_info_log_wake_event("sysctl_wake_pkt_event_notify", &delay_wake_pkt_event.npi_ev_wake_pkt_attributed);
		} else if (delay_wake_pkt_event.npi_wp_code == KEV_POWER_UNATTRIBUTED_WAKE) {
			net_port_info_log_una_wake_event("sysctl_wake_pkt_event_notify", &delay_wake_pkt_event.npi_ev_wake_pkt_unattributed);
		}
	}
#endif /* (DEBUG || DEVELOPMENT) */

	lck_rw_lock_exclusive(&net_port_entry_head_lock);

	if (last_wake_phy_if_delay_wake_pkt == true && val == last_wake_phy_if_family) {
		last_wake_phy_if_delay_wake_pkt = false;

		if (delay_wake_pkt_event.npi_wp_code == KEV_POWER_WAKE_PACKET) {
			if (is_attributed_wake_already_notified(NULL) == false) {
				deliver_attributed_wake_packet_event(&delay_wake_pkt_event.npi_ev_wake_pkt_attributed);
			} else {
				os_log(wake_packet_log_handle, "sysctl_wake_pkt_event_notify attributed_wake_already_notified");
			}
		} else if (delay_wake_pkt_event.npi_wp_code == KEV_POWER_UNATTRIBUTED_WAKE) {
			if (is_unattributed_wake_already_notified(NULL)) {
				deliver_unattributed_wake_packet_event(&delay_wake_pkt_event.npi_ev_wake_pkt_unattributed);
			} else {
				os_log(wake_packet_log_handle, "sysctl_wake_pkt_event_notify unattributed_wake_already_notified");
			}
		} else {
			if_ports_used_stats.ifpu_wake_pkt_event_notify_in_vain += 1;
			os_log(wake_packet_log_handle, "sysctl_wake_pkt_event_notify bad npi_wp_code");
		}
	} else {
		if_ports_used_stats.ifpu_wake_pkt_event_notify_in_vain += 1;
		os_log(wake_packet_log_handle, "sysctl_wake_pkt_event_notify in vain");
	}
	lck_rw_unlock_exclusive(&net_port_entry_head_lock);

	return 0;
}

static void
if_set_delay_wake_flags(ifnet_t ifp, bool delay)
{
	if (delay) {
		if_set_xflags(ifp, IFXF_DELAYWAKEPKTEVENT);
		if_clear_xflags(ifp, IFXF_INBAND_WAKE_PKT_TAGGING);
	} else {
		if_clear_xflags(ifp, IFXF_DELAYWAKEPKTEVENT);
		if_set_xflags(ifp, IFXF_INBAND_WAKE_PKT_TAGGING);
	}
}

int
sysctl_wake_pkt_event_delay_if_families SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	long long val = npi_wake_packet_event_delay_if_families;
	int error;
	int changed = 0;
	uint32_t old_value = npi_wake_packet_event_delay_if_families;

	error = sysctl_io_number(req, val, sizeof(val), &val, &changed);
	if (error != 0 || req->newptr == 0 || changed == 0) {
		return error;
	}
	if (!IOCurrentTaskHasEntitlement(WAKE_PKT_EVENT_CONTROL_ENTITLEMENT)) {
		return EPERM;
	}
	if (val < 0 || val > UINT32_MAX) {
		return EINVAL;
	}

	/* The value is the bitmap of the functional types to delay */
	old_value = npi_wake_packet_event_delay_if_families;
	npi_wake_packet_event_delay_if_families = (uint32_t)val;

	/* Need to reevalute the capability of doing in-band wake packet tagging */
	if (npi_wake_packet_event_delay_if_families != 0) {
		uint32_t count, i;
		ifnet_t *__counted_by(count) ifp_list;

		error = ifnet_list_get_all(IFNET_FAMILY_ANY, &ifp_list, &count);
		if (error != 0) {
			os_log_error(wake_packet_log_handle,
			    "%s: ifnet_list_get_all() failed %d",
			    __func__, error);
			npi_wake_packet_event_delay_if_families = old_value;
			return error;
		}
		for (i = 0; i < count; i++) {
			ifnet_t ifp = ifp_list[i];
			bool delay = is_wake_pkt_event_delay(ifp->if_family);
			const uint32_t flags = IFXF_INBAND_WAKE_PKT_TAGGING | IFXF_DELAYWAKEPKTEVENT;

			if ((delay && (ifp->if_xflags & flags) != IFXF_DELAYWAKEPKTEVENT) ||
			    (!delay && (ifp->if_xflags & flags) != IFXF_INBAND_WAKE_PKT_TAGGING)) {
				if_set_delay_wake_flags(ifp, delay);

				if (if_ports_used_verbose > 0 || ifp->if_family == IFNET_FAMILY_CELLULAR) {
					os_log(wake_packet_log_handle, "interface %s reset INBAND_WAKE_PKT_TAGGING %d DELAYWAKEPKTEVENT %d",
					    ifp->if_xname,
					    ifp->if_xflags & IFXF_INBAND_WAKE_PKT_TAGGING ? 1 : 0,
					    ifp->if_xflags & IFXF_DELAYWAKEPKTEVENT ? 1 : 0);
				}
			}
		}
		ifnet_list_free_counted_by(ifp_list, count);
	}

	os_log(wake_packet_log_handle, "sysctl_wake_pkt_event_delay_if_families proc %s:%u npi_wake_packet_event_delay_if_families 0x%x -> 0x%x",
	    proc_best_name(current_proc()), proc_selfpid(),
	    old_value, npi_wake_packet_event_delay_if_families);


	return 0;
}

void
init_inband_wake_pkt_tagging_for_family(struct ifnet *ifp)
{
	bool delay = is_wake_pkt_event_delay(ifp->if_family);

	if_set_delay_wake_flags(ifp, delay);

	if (if_ports_used_verbose > 0 || ifp->if_family == IFNET_FAMILY_CELLULAR) {
		os_log(wake_packet_log_handle, "interface %s initialized INBAND_WAKE_PKT_TAGGING %d DELAYWAKEPKTEVENT %d",
		    ifp->if_xname,
		    ifp->if_xflags & IFXF_INBAND_WAKE_PKT_TAGGING ? 1 : 0,
		    ifp->if_xflags & IFXF_DELAYWAKEPKTEVENT ? 1 : 0);
	}
}

#if (DEBUG | DEVELOPMENT)

static int
sysctl_use_fake_lpw SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error = 0;
	int old_value = use_fake_lpw;
	int new_value = *(int *)oidp->oid_arg1;

	error = sysctl_handle_int(oidp, &new_value, 0, req);
	if (error == 0) {
		*(int *)oidp->oid_arg1 = new_value;

		if (new_value != old_value) {
			os_log(wake_packet_log_handle, "use_fake_lpw %d", new_value);
		}
	}
	return error;
}

static int
sysctl_mark_wake_packet_port SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error = 0;
	int new_value = *(int *)oidp->oid_arg1;

	error = sysctl_handle_int(oidp, &new_value, 0, req);
	if (error == 0) {
		if (new_value < 0 || new_value >= UINT16_MAX) {
			error = EINVAL;
			goto done;
		}
		*(int *)oidp->oid_arg1 = new_value;
	}
done:
	return error;
}

static int
sysctl_mark_wake_packet_if SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error = 0;
	char new_value[IFNAMSIZ] = { 0 };
	int changed = 0;

	strbufcpy(new_value, IFNAMSIZ, mark_wake_packet_if, IFNAMSIZ);
	error = sysctl_io_string(req, new_value, IFNAMSIZ, 0, &changed);
	if (error == 0) {
		strbufcpy(mark_wake_packet_if, IFNAMSIZ, new_value, IFNAMSIZ);
	}

	return error;
}

bool
check_wake_mbuf(ifnet_t ifp, protocol_family_t protocol_family, mbuf_ref_t m)
{
	uint8_t ipproto = 0;
	size_t offset = 0;

	/* The protocol and interface must both be specified */
	if (mark_wake_packet_ipproto == 0 || mark_wake_packet_if[0] == 0) {
		return false;
	}
	/* The interface must match */
	if (strlcmp(mark_wake_packet_if, IF_XNAME(ifp), IFNAMSIZ) != 0) {
		return false;
	}
	/* The protocol must match */
	if (protocol_family == PF_INET6) {
		struct ip6_hdr ip6;

		if ((size_t)(m)->m_pkthdr.len < sizeof(struct ip6_hdr)) {
			os_log(wake_packet_log_handle, "check_wake_mbuf: IP6 too short");
			return false;
		}
		mbuf_copydata(m, 0, sizeof(struct ip6_hdr), &ip6);

		if ((ipproto = ip6.ip6_nxt) != mark_wake_packet_ipproto) {
			return false;
		}
		offset = sizeof(struct ip6_hdr);
	} else if (protocol_family == PF_INET) {
		struct ip ip;

		if ((size_t)(m)->m_pkthdr.len < sizeof(struct ip)) {
			os_log(wake_packet_log_handle, "check_wake_mbuf: IP too short");
			return false;
		}
		mbuf_copydata(m, 0, sizeof(struct ip), &ip);

		if ((ipproto = ip.ip_p) != mark_wake_packet_ipproto) {
			return false;
		}
		offset = sizeof(struct ip);
	}

	/* Check the ports for TCP and UDP */
	if (ipproto == IPPROTO_TCP) {
		struct tcphdr th;

		if ((size_t)(m)->m_pkthdr.len < offset + sizeof(struct tcphdr)) {
			os_log(wake_packet_log_handle, "check_wake_mbuf: TCP too short");
			return false;
		}
		mbuf_copydata(m, offset, sizeof(struct tcphdr), &th);

		if (mark_wake_packet_local_port != 0 &&
		    ntohs(th.th_dport) != mark_wake_packet_local_port) {
			return false;
		}
		if (mark_wake_packet_remote_port != 0 &&
		    ntohs(th.th_sport) != mark_wake_packet_remote_port) {
			return false;
		}
		return true;
	} else if (ipproto == IPPROTO_UDP) {
		struct udphdr uh;

		if ((size_t)(m)->m_pkthdr.len < offset + sizeof(struct udphdr)) {
			os_log(wake_packet_log_handle, "check_wake_mbufL UDP too short");
			return false;
		}
		mbuf_copydata(m, offset, sizeof(struct udphdr), &uh);

		if (mark_wake_packet_local_port != 0 &&
		    ntohs(uh.uh_dport) != mark_wake_packet_local_port) {
			return false;
		}
		if (mark_wake_packet_remote_port != 0 &&
		    ntohs(uh.uh_sport) != mark_wake_packet_remote_port) {
			return false;
		}
		return true;
	}

	return ipproto == mark_wake_packet_ipproto;
}

bool
check_wake_pkt(ifnet_t ifp __unused, struct __kern_packet *pkt)
{
	/* The protocol and interface must both be specified */
	if (mark_wake_packet_ipproto == 0 || mark_wake_packet_if[0] == 0) {
		return false;
	}
	/* The interface must match */
	if (strlcmp(mark_wake_packet_if, IF_XNAME(ifp), IFNAMSIZ) != 0) {
		return false;
	}
	/* Cannot deal with fragments */
	if (pkt->pkt_flow_ip_is_frag && !pkt->pkt_flow_ip_is_first_frag) {
		return false;
	}
	/* Check the ports for TCP and UDP */
	if (pkt->pkt_flow_ip_proto == IPPROTO_TCP) {
		struct tcphdr * __single th = __unsafe_forge_single(struct tcphdr *, pkt->pkt_flow_tcp_hdr);
		if (th == NULL) {
			return false;
		}
		if (mark_wake_packet_local_port != 0 &&
		    ntohs(th->th_dport) != mark_wake_packet_local_port) {
			return false;
		}
		if (mark_wake_packet_remote_port != 0 &&
		    ntohs(th->th_sport) != mark_wake_packet_remote_port) {
			return false;
		}
		return true;
	} else if (pkt->pkt_flow_ip_proto == IPPROTO_UDP) {
		struct udphdr * __single uh = __unsafe_forge_single(struct udphdr *, pkt->pkt_flow_udp_hdr);
		if (uh == NULL) {
			return false;
		}
		if (mark_wake_packet_local_port != 0 &&
		    ntohs(uh->uh_dport) != mark_wake_packet_local_port) {
			return false;
		}
		if (mark_wake_packet_remote_port != 0 &&
		    ntohs(uh->uh_sport) != mark_wake_packet_remote_port) {
			return false;
		}
	}
	return pkt->pkt_flow_ip_proto == mark_wake_packet_ipproto;
}

#endif /* (DEBUG | DEVELOPMENT) */
