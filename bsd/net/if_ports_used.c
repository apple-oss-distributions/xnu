/*
 * Copyright (c) 2017-2021 Apple Inc. All rights reserved.
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
#include <sys/sysctl.h>
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

#include <kern/locks.h>
#include <kern/zalloc.h>

#include <libkern/libkern.h>

#include <net/kpi_interface.h>
#include <net/if_var.h>
#include <net/if_ports_used.h>

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

#include <os/log.h>

#define ESP_HDR_SIZE 4
#define PORT_ISAKMP 500
#define PORT_ISAKMP_NATT 4500   /* rfc3948 */

#define IF_XNAME(ifp) ((ifp) != NULL ? (ifp)->if_xname : "")

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

int sysctl_new_test_wakeuuid SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, new_test_wakeuuid,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_new_test_wakeuuid, "S,uuid_t", "");

int sysctl_clear_test_wakeuuid SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO, clear_test_wakeuuid,
    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    sysctl_clear_test_wakeuuid, "S,uuid_t", "");

SYSCTL_OPAQUE(_net_link_generic_system_port_used, OID_AUTO, test_wakeuuid,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    test_wakeuuid, sizeof(uuid_t), "S,uuid_t", "");
#endif /* (DEVELOPMENT || DEBUG) */

static int sysctl_get_ports_used SYSCTL_HANDLER_ARGS;
SYSCTL_NODE(_net_link_generic_system, OID_AUTO, get_ports_used,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    sysctl_get_ports_used, "");

static int if_ports_used_verbose = 0;
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

struct net_port_info_wake_event last_attributed_wake_event;
int sysctl_last_attributed_wake_event SYSCTL_HANDLER_ARGS;
static SYSCTL_PROC(_net_link_generic_system_port_used, OID_AUTO,
    last_attributed_wake_event, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_last_attributed_wake_event, "S,net_port_info_wake_event", "");


static bool has_notified_wake_pkt = false;
static bool has_notified_unattributed_wake = false;

static LCK_GRP_DECLARE(net_port_entry_head_lock_group, "net port entry lock");
static LCK_MTX_DECLARE(net_port_entry_head_lock, &net_port_entry_head_lock_group);


struct net_port_entry {
	SLIST_ENTRY(net_port_entry)     npe_list_next;
	TAILQ_ENTRY(net_port_entry)     npe_hash_next;
	struct net_port_info            npe_npi;
};

static KALLOC_TYPE_DEFINE(net_port_entry_zone, struct net_port_entry, NET_KT_DEFAULT);

static SLIST_HEAD(net_port_entry_list, net_port_entry) net_port_entry_list =
    SLIST_HEAD_INITIALIZER(&net_port_entry_list);

struct timeval wakeuiid_last_check;


#if (DEBUG | DEVELOPMENT)
static int64_t npi_search_list_total = 0;
SYSCTL_QUAD(_net_link_generic_system_port_used, OID_AUTO, npi_search_list_total,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &npi_search_list_total, "");

static int64_t npi_search_list_max = 0;
SYSCTL_QUAD(_net_link_generic_system_port_used, OID_AUTO, npi_search_list_max,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &npi_search_list_max, "");
#endif /* (DEBUG | DEVELOPMENT) */

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

static TAILQ_HEAD(net_port_entry_hash_table, net_port_entry) * net_port_entry_hash_table = NULL;

/*
 * Initialize IPv4 source address hash table.
 */
void
if_ports_used_init(void)
{
	if (net_port_entry_hash_table != NULL) {
		return;
	}

	net_port_entry_hash_table = zalloc_permanent(
		NPE_HASH_BUCKET_COUNT * sizeof(*net_port_entry_hash_table),
		ZALIGN_PTR);
}

static void
net_port_entry_list_clear(void)
{
	struct net_port_entry *npe;

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_OWNED);

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
get_test_wake_uuid(uuid_string_t wakeuuid_str, size_t len)
{
	if (__improbable(use_test_wakeuuid)) {
		if (!uuid_is_null(test_wakeuuid)) {
			if (wakeuuid_str != NULL && len != 0) {
				uuid_unparse(test_wakeuuid, wakeuuid_str);
			}
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
}

static bool
is_wakeuuid_set(void)
{
	/*
	 * IOPMCopySleepWakeUUIDKey() tells if SleepWakeUUID is currently set
	 * That means we are currently in a sleep/wake cycle
	 */
	return get_test_wake_uuid(NULL, 0) || IOPMCopySleepWakeUUIDKey(NULL, 0);
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
		wakeuuid_is_set = get_test_wake_uuid(wakeuuid_str,
		    sizeof(wakeuuid_str));
	} else {
		wakeuuid_is_set = IOPMCopySleepWakeUUIDKey(wakeuuid_str,
		    sizeof(wakeuuid_str));
	}

	if (wakeuuid_is_set) {
		if (uuid_parse(wakeuuid_str, wakeuuid) != 0) {
			os_log(OS_LOG_DEFAULT,
			    "%s: IOPMCopySleepWakeUUIDKey got bad value %s\n",
			    __func__, wakeuuid_str);
			wakeuuid_is_set = false;
		}
	}

	if (!wakeuuid_is_set) {
		if (ifp != NULL) {
			if (if_ports_used_verbose > 0) {
				os_log_info(OS_LOG_DEFAULT,
				    "%s: SleepWakeUUID not set, "
				    "don't update the port list for %s\n",
				    __func__, ifp != NULL ? if_name(ifp) : "");
			}
			if_ports_used_stats.ifpu_wakeuuid_not_set_count += 1;
			microtime(&wakeuuid_not_set_last_time);
			strlcpy(wakeuuid_not_set_last_if, if_name(ifp),
			    sizeof(wakeuuid_not_set_last_if));
		}
		return;
	}

	lck_mtx_lock(&net_port_entry_head_lock);
	if (uuid_compare(wakeuuid, current_wakeuuid) != 0) {
		net_port_entry_list_clear();
		uuid_copy(current_wakeuuid, wakeuuid);
		microtime(&wakeuuid_last_update_time);
		updated = true;

		has_notified_wake_pkt = false;
		has_notified_unattributed_wake = false;

		memset(&last_attributed_wake_event, 0, sizeof(last_attributed_wake_event));
	}
	/*
	 * Record the time last checked
	 */
	microuptime(&wakeuiid_last_check);
	lck_mtx_unlock(&net_port_entry_head_lock);

	if (updated && if_ports_used_verbose > 0) {
		uuid_string_t uuid_str;

		uuid_unparse(current_wakeuuid, uuid_str);
		os_log(OS_LOG_DEFAULT, "%s: current wakeuuid %s",
		    __func__, uuid_str);
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

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_OWNED);

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
			os_log(OS_LOG_DEFAULT, "%s: wakeuuid not set not adding "
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
		os_log(OS_LOG_DEFAULT, "%s: zalloc() failed for "
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

	lck_mtx_lock(&net_port_entry_head_lock);

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
			os_log(OS_LOG_DEFAULT, "%s: num %u for "
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
			os_log(OS_LOG_DEFAULT, "%s: already added "
			    "port: %u flags: 0x%x if: %u pid: %u epid %u",
			    __func__,
			    ntohs(npi->npi_local_port),
			    npi->npi_flags,
			    npi->npi_if_index,
			    npi->npi_owner_pid,
			    npi->npi_effective_pid);
		}
	}

	lck_mtx_unlock(&net_port_entry_head_lock);

	if (entry_added == false) {
		zfree(net_port_entry_zone, npe);
	}
	return entry_added;
}

#if (DEVELOPMENT || DEBUG)
int
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

int
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

	return SYSCTL_OUT(req, &wakeuuid_not_set_last_if, strlen(wakeuuid_not_set_last_if) + 1);
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
	lck_mtx_lock(&net_port_entry_head_lock);

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
	lck_mtx_unlock(&net_port_entry_head_lock);

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
	int *name = (int *)arg1;
	int namelen = arg2;
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
	/*
	 * 3 is the required number of parameters: ifindex, protocol and flags
	 */
	if (namelen != 3) {
		error = ENOENT;
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
		os_log(OS_LOG_DEFAULT, "%s: ifindex %u too big", __func__, ifindex);
		return false;
	}

	if (ifindex != 0) {
		npi.npi_if_index = (uint16_t)ifindex;
	} else if (inp->inp_last_outifp != NULL) {
		npi.npi_if_index = (uint16_t)inp->inp_last_outifp->if_index;
	}
	if (IF_INDEX_IN_RANGE(npi.npi_if_index)) {
		struct ifnet *ifp = ifindex2ifnet[npi.npi_if_index];
		if (ifp != NULL && IFNET_IS_COMPANION_LINK(ifp)) {
			npi.npi_flags |= NPIF_COMPLINK;
		}
	}

	npi.npi_flags |= NPIF_SOCKET;

	npi.npi_timestamp.tv_sec = (int32_t)wakeuiid_last_check.tv_sec;
	npi.npi_timestamp.tv_usec = wakeuiid_last_check.tv_usec;

	if (so->so_options & SO_NOWAKEFROMSLEEP) {
		npi.npi_flags |= NPIF_NOWAKE;
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
		os_log(OS_LOG_DEFAULT, "%s: unexpected protocol %u for inp %p", __func__,
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
			strlcpy(npi.npi_effective_pname, npi.npi_owner_pname,
			    sizeof(npi.npi_effective_pname));
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
		os_log(OS_LOG_DEFAULT, "%s: ifindex %u too big", __func__, ifindex);
		return false;
	}
	npi.npi_if_index = (uint16_t)ifindex;
	if (IF_INDEX_IN_RANGE(ifindex)) {
		struct ifnet *ifp = ifindex2ifnet[ifindex];
		if (ifp != NULL && IFNET_IS_COMPANION_LINK(ifp)) {
			npi.npi_flags |= NPIF_COMPLINK;
		}
	}

	npi.npi_flags |= NPIF_CHANNEL;

	npi.npi_timestamp.tv_sec = (int32_t)wakeuiid_last_check.tv_sec;
	npi.npi_timestamp.tv_usec = wakeuiid_last_check.tv_usec;

	if (ns_flags & NETNS_NOWAKEFROMSLEEP) {
		npi.npi_flags |= NPIF_NOWAKE;
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
		os_log(OS_LOG_DEFAULT, "%s: unexpected protocol %u for nfi %p",
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
	strlcpy(npi.npi_owner_pname, nfi->nfi_owner_name,
	    sizeof(npi.npi_owner_pname));

	/*
	 * Get the proc UUID from the pid as the the proc UUID is not present
	 * in the flow_entry
	 */
	proc_t proc = proc_find(npi.npi_owner_pid);
	if (proc != PROC_NULL) {
		proc_getexecutableuuid(proc, npi.npi_owner_uuid, sizeof(npi.npi_owner_uuid));
		proc_rele(proc);
	}
	if (nfi->nfi_effective_pid != -1) {
		npi.npi_effective_pid = nfi->nfi_effective_pid;
		strlcpy(npi.npi_effective_pname, nfi->nfi_effective_name,
		    sizeof(npi.npi_effective_pname));
		uuid_copy(npi.npi_effective_uuid, fe->fe_eproc_uuid);
	} else {
		npi.npi_effective_pid = npi.npi_owner_pid;
		strlcpy(npi.npi_effective_pname, npi.npi_owner_pname,
		    sizeof(npi.npi_effective_pname));
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
	os_log(OS_LOG_DEFAULT, "%s net_port_info if_index %u arch %s family %s proto %s local %s:%u foreign %s:%u pid: %u epid %u",
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

#define NPI_MATCH_IPV4 (NPIF_IPV4 | NPIF_TCP | NPIF_UDP)
#define NPI_MATCH_IPV6 (NPIF_IPV6 | NPIF_TCP | NPIF_UDP)

static bool
net_port_info_match_npi(struct net_port_entry *npe, const struct net_port_info *in_npi,
    struct net_port_entry **best_match)
{
	if (__improbable(net_wake_pkt_debug > 1)) {
		net_port_info_log_npi("  ", &npe->npe_npi);
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
				*best_match = npe;
				return true;
			}
		}
		if ((npe->npe_npi.npi_flags & NPIF_IPV6) && (npe->npe_npi.npi_flags & NPIF_IPV6)) {
			if (memcmp(&npe->npe_npi.npi_local_addr_, &in_npi->npi_local_addr_,
			    sizeof(union in_addr_4_6)) == 0 &&
			    memcmp(&npe->npe_npi.npi_foreign_addr_, &in_npi->npi_foreign_addr_,
			    sizeof(union in_addr_4_6)) == 0) {
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

/*
 *
 */
static bool
net_port_info_find_match(struct net_port_info *in_npi)
{
	struct net_port_entry *npe;
	struct net_port_entry *best_match = NULL;

	lck_mtx_lock(&net_port_entry_head_lock);

	uint32_t count = 0;
	TAILQ_FOREACH(npe, NPE_HASH_HEAD(in_npi->npi_local_port), npe_hash_next) {
		count += 1;
		if (net_port_info_match_npi(npe, in_npi, &best_match)) {
			break;
		}
	}

	if (best_match != NULL) {
		best_match->npe_npi.npi_flags |= NPIF_WAKEPKT;
		in_npi->npi_owner_pid = best_match->npe_npi.npi_owner_pid;
		in_npi->npi_effective_pid = best_match->npe_npi.npi_effective_pid;
		strlcpy(in_npi->npi_owner_pname, best_match->npe_npi.npi_owner_pname,
		    sizeof(in_npi->npi_owner_pname));
		strlcpy(in_npi->npi_effective_pname, best_match->npe_npi.npi_effective_pname,
		    sizeof(in_npi->npi_effective_pname));
		uuid_copy(in_npi->npi_owner_uuid, best_match->npe_npi.npi_owner_uuid);
		uuid_copy(in_npi->npi_effective_uuid, best_match->npe_npi.npi_effective_uuid);
	}
	lck_mtx_unlock(&net_port_entry_head_lock);

	if (__improbable(net_wake_pkt_debug > 0)) {
		if (best_match != NULL) {
			net_port_info_log_npi("wake packet match", in_npi);
		} else {
			net_port_info_log_npi("wake packet no match", in_npi);
		}
	}

	return best_match != NULL ? true : false;
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
	os_log(OS_LOG_DEFAULT, "%s if %s (%u) proto %s local %s:%u foreign %s:%u len: %u datalen: %u cflags: 0x%x proto: %u",
	    s != NULL ? s : "",
	    ev->una_wake_pkt_ifname, ev->una_wake_pkt_if_index,
	    ev->una_wake_pkt_flags & NPIF_TCP ? "tcp" : ev->una_wake_pkt_flags ? "udp" :
	    ev->una_wake_pkt_flags & NPIF_ESP ? "esp" : "unknown",
	    lbuf, ntohs(ev->una_wake_pkt_local_port),
	    fbuf, ntohs(ev->una_wake_pkt_foreign_port),
	    ev->una_wake_pkt_total_len, ev->una_wake_pkt_data_len,
	    ev->una_wake_pkt_control_flags, ev->una_wake_pkt_proto);
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
	os_log(OS_LOG_DEFAULT, "%s if %s (%u) proto %s local %s:%u foreign %s:%u len: %u datalen: %u cflags: 0x%x proc %s eproc %s",
	    s != NULL ? s : "",
	    ev->wake_pkt_ifname, ev->wake_pkt_if_index,
	    ev->wake_pkt_flags & NPIF_TCP ? "tcp" : ev->wake_pkt_flags ? "udp" :
	    ev->wake_pkt_flags & NPIF_ESP ? "esp" : "unknown",
	    lbuf, ntohs(ev->wake_pkt_port),
	    fbuf, ntohs(ev->wake_pkt_foreign_port),
	    ev->wake_pkt_total_len, ev->wake_pkt_data_len, ev->wake_pkt_control_flags,
	    ev->wake_pkt_owner_pname, ev->wake_pkt_effective_pname);
}

#endif /* (DEBUG || DEVELOPMENT) */

static void
if_notify_unattributed_wake_mbuf(struct ifnet *ifp, struct mbuf *m,
    struct net_port_info *npi, uint32_t pkt_total_len, uint32_t pkt_data_len,
    uint16_t pkt_control_flags, uint16_t proto)
{
	struct kev_msg ev_msg = {};

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_NOTOWNED);

	lck_mtx_lock(&net_port_entry_head_lock);
	if (has_notified_unattributed_wake) {
		lck_mtx_unlock(&net_port_entry_head_lock);
		if_ports_used_stats.ifpu_dup_unattributed_wake_event += 1;

		if (__improbable(net_wake_pkt_debug > 0)) {
			net_port_info_log_npi("already notified unattributed wake packet", npi);
		}
		return;
	}
	has_notified_unattributed_wake = true;
	lck_mtx_unlock(&net_port_entry_head_lock);

	if_ports_used_stats.ifpu_unattributed_wake_event += 1;

	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_POWER_SUBCLASS;
	ev_msg.event_code  = KEV_POWER_UNATTRIBUTED_WAKE;

	struct net_port_info_una_wake_event event_data = {};
	uuid_copy(event_data.una_wake_uuid, current_wakeuuid);
	event_data.una_wake_pkt_if_index = ifp != NULL ? ifp->if_index : 0;
	event_data.una_wake_pkt_flags = npi->npi_flags;

	event_data.una_wake_pkt_local_port = npi->npi_local_port;
	event_data.una_wake_pkt_foreign_port = npi->npi_foreign_port;
	event_data.una_wake_pkt_local_addr_ = npi->npi_local_addr_;
	event_data.una_wake_pkt_foreign_addr_ = npi->npi_foreign_addr_;

	event_data.una_wake_pkt_total_len = pkt_total_len;
	event_data.una_wake_pkt_data_len = pkt_data_len;
	event_data.una_wake_pkt_control_flags = pkt_control_flags;
	event_data.una_wake_pkt_proto = proto;

	if (ifp != NULL) {
		strlcpy(event_data.una_wake_pkt_ifname, IF_XNAME(ifp),
		    sizeof(event_data.una_wake_pkt_ifname));
	} else {
		if_ports_used_stats.ifpu_unattributed_null_recvif += 1;
	}

	event_data.una_wake_ptk_len = m->m_pkthdr.len > NPI_MAX_UNA_WAKE_PKT_LEN ?
	    NPI_MAX_UNA_WAKE_PKT_LEN : (u_int16_t)m->m_pkthdr.len;

	errno_t error = mbuf_copydata(m, 0, event_data.una_wake_ptk_len,
	    (void *)event_data.una_wake_pkt);
	if (error != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data.una_wake_uuid, wake_uuid_str);
		os_log_error(OS_LOG_DEFAULT,
		    "%s: mbuf_copydata() failed with error %d for wake uuid %s",
		    __func__, error, wake_uuid_str);

		if_ports_used_stats.ifpu_unattributed_wake_event_error += 1;
		return;
	}

	ev_msg.dv[0].data_ptr = &event_data;
	ev_msg.dv[0].data_length = sizeof(event_data);

	int result = kev_post_msg(&ev_msg);
	if (result != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data.una_wake_uuid, wake_uuid_str);
		os_log_error(OS_LOG_DEFAULT,
		    "%s: kev_post_msg() failed with error %d for wake uuid %s",
		    __func__, result, wake_uuid_str);

		if_ports_used_stats.ifpu_unattributed_wake_event_error += 1;
	}

#if (DEBUG || DEVELOPMENT)
	net_port_info_log_una_wake_event("unattributed wake packet event", &event_data);
#endif /* (DEBUG || DEVELOPMENT) */
}

static void
if_notify_wake_packet(struct ifnet *ifp, struct net_port_info *npi,
    uint32_t pkt_total_len, uint32_t pkt_data_len, uint16_t pkt_control_flags)
{
	struct kev_msg ev_msg = {};

	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_POWER_SUBCLASS;
	ev_msg.event_code  = KEV_POWER_WAKE_PACKET;

	struct net_port_info_wake_event event_data = {};

	uuid_copy(event_data.wake_uuid, current_wakeuuid);
	event_data.wake_pkt_if_index = ifp->if_index;
	event_data.wake_pkt_port = npi->npi_local_port;
	event_data.wake_pkt_flags = npi->npi_flags;
	event_data.wake_pkt_owner_pid = npi->npi_owner_pid;
	event_data.wake_pkt_effective_pid = npi->npi_effective_pid;
	strlcpy(event_data.wake_pkt_owner_pname, npi->npi_owner_pname,
	    sizeof(event_data.wake_pkt_owner_pname));
	strlcpy(event_data.wake_pkt_effective_pname, npi->npi_effective_pname,
	    sizeof(event_data.wake_pkt_effective_pname));
	uuid_copy(event_data.wake_pkt_owner_uuid, npi->npi_owner_uuid);
	uuid_copy(event_data.wake_pkt_effective_uuid, npi->npi_effective_uuid);

	event_data.wake_pkt_foreign_port = npi->npi_foreign_port;
	event_data.wake_pkt_local_addr_ = npi->npi_local_addr_;
	event_data.wake_pkt_foreign_addr_ = npi->npi_foreign_addr_;
	strlcpy(event_data.wake_pkt_ifname, IF_XNAME(ifp), sizeof(event_data.wake_pkt_ifname));

	event_data.wake_pkt_total_len = pkt_total_len;
	event_data.wake_pkt_data_len = pkt_data_len;
	event_data.wake_pkt_control_flags = pkt_control_flags;

	ev_msg.dv[0].data_ptr = &event_data;
	ev_msg.dv[0].data_length = sizeof(event_data);

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_NOTOWNED);

	lck_mtx_lock(&net_port_entry_head_lock);

	if (has_notified_wake_pkt) {
		lck_mtx_unlock(&net_port_entry_head_lock);
		if_ports_used_stats.ifpu_dup_wake_pkt_event += 1;

		if (__improbable(net_wake_pkt_debug > 0)) {
			net_port_info_log_npi("already notified wake packet", npi);
		}
		return;
	}
	has_notified_wake_pkt = true;

	memcpy(&last_attributed_wake_event, &event_data, sizeof(last_attributed_wake_event));

	lck_mtx_unlock(&net_port_entry_head_lock);

	if_ports_used_stats.ifpu_wake_pkt_event += 1;


	int result = kev_post_msg(&ev_msg);
	if (result != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data.wake_uuid, wake_uuid_str);
		os_log_error(OS_LOG_DEFAULT,
		    "%s: kev_post_msg() failed with error %d for wake uuid %s",
		    __func__, result, wake_uuid_str);

		if_ports_used_stats.ifpu_wake_pkt_event_error += 1;
	}
#if (DEBUG || DEVELOPMENT)
	net_port_info_log_wake_event("attributed wake packet event", &event_data);
#endif /* (DEBUG || DEVELOPMENT) */
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
			os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(ESP_HDR_SIZE) error %d",
			    __func__, error);
		} else if (payload[0] == 0 && payload[1] == 0 &&
		    payload[2] == 0 && payload[3] == 0) {
			return false;
		}
	}
	return true;
}

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

	if ((m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT) == 0) {
		if_ports_used_stats.ifpu_match_wake_pkt_no_flag += 1;
		os_log_error(OS_LOG_DEFAULT, "%s: called PKTF_WAKE_PKT not set from %s",
		    __func__, ifp != NULL ? IF_XNAME(ifp) : "");
		return;
	}

	if_ports_used_stats.ifpu_so_match_wake_pkt += 1;
	npi.npi_flags |= NPIF_SOCKET; /* For logging */
	pkt_total_len = m->m_pkthdr.len;
	pkt_data_len = pkt_total_len;

	if (ifp != NULL) {
		npi.npi_if_index = ifp->if_index;
		if (IFNET_IS_COMPANION_LINK(ifp)) {
			npi.npi_flags |= NPIF_COMPLINK;
		}
	}

	if (proto_family == PF_INET) {
		struct ip iphdr = {};

		if_ports_used_stats.ifpu_ipv4_wake_pkt += 1;

		error = mbuf_copydata(m, 0, sizeof(struct ip), &iphdr);
		if (error != 0) {
			os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(ip) error %d",
			    __func__, error);
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
				os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(tcphdr) error %d",
				    __func__, error);
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
				os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(udphdr) error %d",
				    __func__, error);
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
			os_log(OS_LOG_DEFAULT, "%s: unexpected IPv4 protocol %u from %s",
			    __func__, iphdr.ip_p, IF_XNAME(ifp));
			goto failed;
		}
	} else if (proto_family == PF_INET6) {
		struct ip6_hdr ip6_hdr = {};

		if_ports_used_stats.ifpu_ipv6_wake_pkt += 1;

		error = mbuf_copydata(m, 0, sizeof(struct ip6_hdr), &ip6_hdr);
		if (error != 0) {
			os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(ip6_hdr) error %d",
			    __func__, error);
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
				os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(ip6_frag) error %d",
				    __func__, error);
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
				os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(tcphdr) error %d",
				    __func__, error);
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
				os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata(udphdr) error %d",
				    __func__, error);
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

			os_log(OS_LOG_DEFAULT, "%s: unexpected IPv6 protocol %u from %s",
			    __func__, ip6_hdr.ip6_nxt, IF_XNAME(ifp));
			goto failed;
		}
	} else {
		if_ports_used_stats.ifpu_bad_family_wake_pkt += 1;
		os_log(OS_LOG_DEFAULT, "%s: unexpected protocol family %d from %s",
		    __func__, proto_family, IF_XNAME(ifp));
		goto failed;
	}
	if (ifp == NULL) {
		goto failed;
	}

	found = net_port_info_find_match(&npi);
	if (found) {
		if_notify_wake_packet(ifp, &npi,
		    pkt_total_len, pkt_data_len, pkt_control_flags);
	} else {
		if_notify_unattributed_wake_mbuf(ifp, m, &npi,
		    pkt_total_len, pkt_data_len, pkt_control_flags, pkt_proto);
	}
	return;
failed:
	if_notify_unattributed_wake_mbuf(ifp, m, &npi,
	    pkt_total_len, pkt_data_len, pkt_control_flags, pkt_proto);
}

#if SKYWALK

static void
if_notify_unattributed_wake_pkt(struct ifnet *ifp, struct __kern_packet *pkt,
    struct net_port_info *npi, uint32_t pkt_total_len, uint32_t pkt_data_len,
    uint16_t pkt_control_flags, uint16_t proto)
{
	struct kev_msg ev_msg = {};

	LCK_MTX_ASSERT(&net_port_entry_head_lock, LCK_MTX_ASSERT_NOTOWNED);

	lck_mtx_lock(&net_port_entry_head_lock);
	if (has_notified_unattributed_wake) {
		lck_mtx_unlock(&net_port_entry_head_lock);
		if_ports_used_stats.ifpu_dup_unattributed_wake_event += 1;

		if (__improbable(net_wake_pkt_debug > 0)) {
			net_port_info_log_npi("already notified unattributed wake packet", npi);
		}
		return;
	}
	has_notified_unattributed_wake = true;
	lck_mtx_unlock(&net_port_entry_head_lock);

	if_ports_used_stats.ifpu_unattributed_wake_event += 1;

	if (ifp == NULL) {
		os_log(OS_LOG_DEFAULT, "%s: receive interface is NULL",
		    __func__);
		if_ports_used_stats.ifpu_unattributed_null_recvif += 1;
	}

	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_POWER_SUBCLASS;
	ev_msg.event_code  = KEV_POWER_UNATTRIBUTED_WAKE;

	struct net_port_info_una_wake_event event_data = {};
	uuid_copy(event_data.una_wake_uuid, current_wakeuuid);
	event_data.una_wake_pkt_if_index = ifp != NULL ? ifp->if_index : 0;
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
	if (ifp != NULL) {
		strlcpy(event_data.una_wake_pkt_ifname, IF_XNAME(ifp),
		    sizeof(event_data.una_wake_pkt_ifname));
	}

	event_data.una_wake_pkt_total_len = pkt_total_len;
	event_data.una_wake_pkt_data_len = pkt_data_len;
	event_data.una_wake_pkt_control_flags = pkt_control_flags;
	event_data.una_wake_pkt_proto = proto;

	ev_msg.dv[0].data_ptr = &event_data;
	ev_msg.dv[0].data_length = sizeof(event_data);

	int result = kev_post_msg(&ev_msg);
	if (result != 0) {
		uuid_string_t wake_uuid_str;

		uuid_unparse(event_data.una_wake_uuid, wake_uuid_str);
		os_log_error(OS_LOG_DEFAULT,
		    "%s: kev_post_msg() failed with error %d for wake uuid %s",
		    __func__, result, wake_uuid_str);

		if_ports_used_stats.ifpu_unattributed_wake_event_error += 1;
	}
#if (DEBUG || DEVELOPMENT)
	net_port_info_log_una_wake_event("unattributed wake packet event", &event_data);
#endif /* (DEBUG || DEVELOPMENT) */
}

void
if_ports_used_match_pkt(struct ifnet *ifp, struct __kern_packet *pkt)
{
	struct net_port_info npi = {};
	bool found = false;
	uint32_t pkt_total_len = 0;
	uint32_t pkt_data_len = 0;
	uint16_t pkt_control_flags = 0;
	uint16_t pkt_proto = 0;

	if ((pkt->pkt_pflags & PKT_F_WAKE_PKT) == 0) {
		if_ports_used_stats.ifpu_match_wake_pkt_no_flag += 1;
		os_log_error(OS_LOG_DEFAULT, "%s: called PKT_F_WAKE_PKT not set from %s",
		    __func__, IF_XNAME(ifp));
		return;
	}

	if_ports_used_stats.ifpu_ch_match_wake_pkt += 1;
	npi.npi_flags |= NPIF_CHANNEL; /* For logging */
	pkt_total_len = pkt->pkt_flow_ip_hlen +
	    pkt->pkt_flow_tcp_hlen + pkt->pkt_flow_ulen;
	pkt_data_len = pkt->pkt_flow_ulen;

	if (ifp != NULL) {
		npi.npi_if_index = ifp->if_index;
		if (IFNET_IS_COMPANION_LINK(ifp)) {
			npi.npi_flags |= NPIF_COMPLINK;
		}
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

		os_log(OS_LOG_DEFAULT, "%s: unexpected protocol family %u from %s",
		    __func__, pkt->pkt_flow_ip_ver, IF_XNAME(ifp));
		goto failed;
	}
	pkt_proto = pkt->pkt_flow_ip_ver;

	/*
	 * Check if this is a fragment that is not the first fragment
	 */
	if (pkt->pkt_flow_ip_is_frag && !pkt->pkt_flow_ip_is_first_frag) {
		os_log(OS_LOG_DEFAULT, "%s: unexpected wake fragment from %s",
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
		struct tcphdr *tcp = (struct tcphdr *)pkt->pkt_flow_tcp_hdr;
		if (tcp == NULL) {
			os_log(OS_LOG_DEFAULT, "%s: pkt with unassigned TCP header from %s",
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
		struct udphdr *uh = (struct udphdr *)pkt->pkt_flow_udp_hdr;
		if (uh == NULL) {
			os_log(OS_LOG_DEFAULT, "%s: pkt with unassigned UDP header from %s",
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

		os_log(OS_LOG_DEFAULT, "%s: unexpected IP protocol %u from %s",
		    __func__, pkt->pkt_flow_ip_proto, IF_XNAME(ifp));
		goto failed;
	}

	if (ifp == NULL) {
		goto failed;
	}

	found = net_port_info_find_match(&npi);
	if (found) {
		if_notify_wake_packet(ifp, &npi,
		    pkt_total_len, pkt_data_len, pkt_control_flags);
	} else {
		if_notify_unattributed_wake_pkt(ifp, pkt, &npi,
		    pkt_total_len, pkt_data_len, pkt_control_flags, pkt_proto);
	}
	return;
failed:
	if_notify_unattributed_wake_pkt(ifp, pkt, &npi,
	    pkt_total_len, pkt_data_len, pkt_control_flags, pkt_proto);
}
#endif /* SKYWALK */

int
sysctl_last_attributed_wake_event SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	size_t len = sizeof(struct net_port_info_wake_event);

	if (req->oldptr != 0) {
		len = MIN(req->oldlen, len);
	}
	lck_mtx_lock(&net_port_entry_head_lock);
	int error = SYSCTL_OUT(req, &last_attributed_wake_event, len);
	lck_mtx_unlock(&net_port_entry_head_lock);

	return error;
}
