/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * LOCKING STRATEGY
 *
 * The struct socket's so_flow_db field (struct soflow_db and its hash entries
 * struct soflow_hash_entry) is protected by the socket lock. This covers all the
 * socket paths that calls soflow_get_flow() as well as the garbage collection.
 * For the socket detach path, soflow_detach() cannot assume the socket lock is
 * held. Thus, reference counts are added to both struct soflow_db and struct
 * soflow_hash_entry to avoid access after freed issues.
 *
 * The global list, soflow_entry_head, keeps track of all struct soflow_hash_entry
 * entries which is used by garbage collection when detecting idle entries.  This list
 * is protected by the global lock soflow_lck_rw.
 *
 */

#include <sys/types.h>
#include <sys/kern_control.h>
#include <sys/queue.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <kern/zalloc.h>
#include <kern/debug.h>
#include <net/ntstat.h>
#include <netinet6/in6_var.h>

#define _IP_VHL
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <string.h>
#include <libkern/libkern.h>
#include <kern/socket_flows.h>

extern struct inpcbinfo ripcbinfo;

/*
 * Per-Socket Flow Management
 */

static int soflow_log_level = LOG_ERR;
static int soflow_log_port = 0;
static int soflow_log_pid = 0;
static int soflow_log_proto = 0;
static int soflow_nstat_disable = 0;
static int soflow_disable = 0;
static os_log_t soflow_log_handle = NULL;

/*
 * Sysctls for debug logs control
 */
SYSCTL_NODE(_net, OID_AUTO, soflow, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "soflow");

SYSCTL_INT(_net_soflow, OID_AUTO, log_level, CTLFLAG_RW | CTLFLAG_LOCKED,
    &soflow_log_level, 0, "");

SYSCTL_INT(_net_soflow, OID_AUTO, log_port, CTLFLAG_RW | CTLFLAG_LOCKED,
    &soflow_log_port, 0, "");

SYSCTL_INT(_net_soflow, OID_AUTO, log_pid, CTLFLAG_RW | CTLFLAG_LOCKED,
    &soflow_log_pid, 0, "");

SYSCTL_INT(_net_soflow, OID_AUTO, log_proto, CTLFLAG_RW | CTLFLAG_LOCKED,
    &soflow_log_proto, 0, "");

SYSCTL_INT(_net_soflow, OID_AUTO, nstat_disable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &soflow_nstat_disable, 0, "");

SYSCTL_INT(_net_soflow, OID_AUTO, disable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &soflow_disable, 0, "");

#define SOFLOW_LOG(level, so, debug, fmt, ...)                                                                      \
do {                                                                                                                \
    if (soflow_log_level >= level && debug && soflow_log_handle) {                                                  \
	if (level == LOG_ERR) {                                                                                         \
	    os_log_error(soflow_log_handle, "SOFLOW - %s:%d <pid %d so %llx> " fmt "\n", __FUNCTION__, __LINE__,        \
	             so ? SOFLOW_SOCKET_PID(so) : 0, so ? (uint64_t)VM_KERNEL_ADDRPERM(so) : 0, ##__VA_ARGS__);         \
	} else {                                                                                                        \
	    os_log(soflow_log_handle, "SOFLOW - %s:%d <pid %d so %llx> " fmt "\n", __FUNCTION__, __LINE__,              \
	       so ? SOFLOW_SOCKET_PID(so) : 0, so ? (uint64_t)VM_KERNEL_ADDRPERM(so) : 0, ##__VA_ARGS__);               \
	}                                                                                                               \
    }                                                                                                               \
} while (0)

#define SOFLOW_ENTRY_LOG(level, so, entry, debug, msg)                                                              \
do {                                                                                                                \
    if (soflow_log_level >= level && entry && debug) {                                                              \
    soflow_entry_log(level, so, entry, msg);                                                                        \
    }                                                                                                               \
} while (0)

#define SOFLOW_HASH_SIZE 16
#define SOFLOW_HASH(laddr, faddr, lport, fport) ((faddr) ^ ((laddr) >> 16) ^ (fport) ^ (lport))

#define SOFLOW_IS_UDP(so) (so && so->so_proto && so->so_proto->pr_type == SOCK_DGRAM && so->so_proto->pr_protocol == IPPROTO_UDP)
#define SOFLOW_GET_SO_PROTO(so) ((so && so->so_proto) ? so->so_proto->pr_protocol : IPPROTO_MAX)

#define SOFLOW_SOCKET_PID(so) ((so->so_flags & SOF_DELEGATED) ? so->e_pid : so->last_pid)

#define SOFLOW_ENABLE_DEBUG(so, entry) \
    ((soflow_log_port == 0 || !entry || soflow_log_port == ntohs(entry->soflow_lport) || soflow_log_port == ntohs(entry->soflow_fport)) && \
     (soflow_log_pid == 0 || !so || soflow_log_pid == SOFLOW_SOCKET_PID(so)) && \
     (soflow_log_proto == 0 || !so || soflow_log_proto == SOFLOW_GET_SO_PROTO(so)))

os_refgrp_decl(static, soflow_refgrp, "soflow_ref_group", NULL);

#define SOFLOW_ENTRY_FREE(entry) \
    if (entry && (os_ref_release(&entry->soflow_ref_count) == 0)) { \
	soflow_entry_free(entry); \
    }

#define SOFLOW_DB_FREE(db) \
    if (db && (os_ref_release(&db->soflow_db_ref_count) == 0)) { \
    soflow_db_free(db); \
    }

LIST_HEAD(soflow_hash_head, soflow_hash_entry);

static int soflow_initialized = 0;
static int soflow_attached_count = 0;

TAILQ_HEAD(soflow_entry_head, soflow_hash_entry) soflow_entry_head;
static LCK_GRP_DECLARE(soflow_lck_grp, "Socket Flow");
static LCK_RW_DECLARE(soflow_lck_rw, &soflow_lck_grp);

#define SOFLOW_LOCK_EXCLUSIVE lck_rw_lock_exclusive(&soflow_lck_rw)
#define SOFLOW_UNLOCK_EXCLUSIVE lck_rw_unlock_exclusive(&soflow_lck_rw)
#define SOFLOW_LOCK_SHARED lck_rw_lock_shared(&soflow_lck_rw)
#define SOFLOW_UNLOCK_SHARED lck_rw_unlock_shared(&soflow_lck_rw)

/*
 * Flow Garbage Collection:
 */
static struct thread *soflow_gc_thread;
static soflow_feat_gc_needed_func soflow_feat_gc_needed_func_ptr = NULL;
static soflow_feat_gc_perform_func soflow_feat_gc_perform_func_ptr = NULL;

#define SOFLOW_GC_IDLE_TO            30  // Flow Idle Timeout in seconds
#define SOFLOW_GC_MAX_COUNT          100 // Max sockets to be handled per run
#define SOFLOW_GC_RUN_INTERVAL_NSEC  (10 * NSEC_PER_SEC)  // GC wakes up every 10 seconds

/*
 * Feature Context Handling:
 */
static soflow_feat_detach_entry_func soflow_feat_detach_entry_func_ptr = NULL;
static soflow_feat_detach_db_func soflow_feat_detach_db_func_ptr = NULL;

static void soflow_gc_thread_func(void *v, wait_result_t w);
static void soflow_gc_expire(void *v, wait_result_t w);
static boolean_t soflow_entry_local_address_needs_update(struct soflow_hash_entry *);
static boolean_t soflow_entry_local_port_needs_update(struct socket *, struct soflow_hash_entry *);

static void
soflow_init(void)
{
	if (soflow_initialized) {
		return;
	}
	soflow_initialized = 1;

	if (soflow_log_handle == NULL) {
		soflow_log_handle = os_log_create("com.apple.xnu.net.soflow", "soflow");
	}

	TAILQ_INIT(&soflow_entry_head);

	// Spawn thread for gargage collection
	if (kernel_thread_start(soflow_gc_thread_func, NULL,
	    &soflow_gc_thread) != KERN_SUCCESS) {
		panic_plain("%s: Can't create SOFLOW GC thread", __func__);
		/* NOTREACHED */
	}
	/* this must not fail */
	VERIFY(soflow_gc_thread != NULL);
}

static void
soflow_entry_log(int level, struct socket *so, struct soflow_hash_entry *entry, const char* msg)
{
#pragma unused(level, msg)
	char local[MAX_IPv6_STR_LEN + 6] = { 0 };
	char remote[MAX_IPv6_STR_LEN + 6] = { 0 };
	const void  *addr;

	// No sock or not UDP, no-op
	if (entry == NULL) {
		return;
	}

	switch (entry->soflow_family) {
	case AF_INET6:
		addr = &entry->soflow_laddr.addr6;
		inet_ntop(AF_INET6, addr, local, sizeof(local));
		addr = &entry->soflow_faddr.addr6;
		inet_ntop(AF_INET6, addr, remote, sizeof(local));
		break;
	case AF_INET:
		addr = &entry->soflow_laddr.addr46.ia46_addr4.s_addr;
		inet_ntop(AF_INET, addr, local, sizeof(local));
		addr = &entry->soflow_faddr.addr46.ia46_addr4.s_addr;
		inet_ntop(AF_INET, addr, remote, sizeof(local));
		break;
	default:
		return;
	}

	SOFLOW_LOG(level, so, entry->soflow_debug, "<%s>: %s <%s(%d) entry %p, featureID %llu> outifp %d lport %d fport %d laddr %s faddr %s hash %X "
	    "<rx p %llu b %llu, tx p %llu b %llu>",
	    msg, entry->soflow_outgoing ? "OUT" : "IN ",
	    SOFLOW_IS_UDP(so) ? "UDP" : "proto", SOFLOW_GET_SO_PROTO(so),
	    entry, entry->soflow_feat_ctxt_id,
	    entry->soflow_outifindex,
	    ntohs(entry->soflow_lport), ntohs(entry->soflow_fport), local, remote,
	    entry->soflow_flowhash,
	    entry->soflow_rxpackets, entry->soflow_rxbytes, entry->soflow_txpackets, entry->soflow_txbytes);
}

bool
soflow_fill_hash_entry_from_address(struct soflow_hash_entry *entry, bool isLocal, struct sockaddr *addr, bool islocalUpdate)
{
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;

	if (entry == NULL || addr == NULL) {
		return FALSE;
	}

	switch (addr->sa_family) {
	case AF_INET:
		sin = satosin(addr);
		if (sin->sin_len != sizeof(*sin)) {
			return FALSE;
		}
		if (isLocal == TRUE) {
			if (sin->sin_port != 0) {
				entry->soflow_lport = sin->sin_port;
				if (islocalUpdate) {
					entry->soflow_lport_updated = TRUE;
				}
			}
			if (sin->sin_addr.s_addr != INADDR_ANY) {
				entry->soflow_laddr.addr46.ia46_addr4.s_addr = sin->sin_addr.s_addr;
				if (islocalUpdate) {
					entry->soflow_laddr_updated = TRUE;
				}
			}
		} else {
			if (sin->sin_port != 0) {
				entry->soflow_fport = sin->sin_port;
			}
			if (sin->sin_addr.s_addr != INADDR_ANY) {
				entry->soflow_faddr.addr46.ia46_addr4.s_addr = sin->sin_addr.s_addr;
			}
		}
		entry->soflow_family = AF_INET;
		return TRUE;
	case AF_INET6:
		sin6 = satosin6(addr);
		if (sin6->sin6_len != sizeof(*sin6)) {
			return FALSE;
		}
		if (isLocal == TRUE) {
			if (sin6->sin6_port != 0) {
				entry->soflow_lport = sin6->sin6_port;
				if (islocalUpdate) {
					entry->soflow_lport_updated = TRUE;
				}
			}
			if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				entry->soflow_laddr.addr6 = sin6->sin6_addr;
				entry->soflow_laddr6_ifscope = sin6->sin6_scope_id;
				in6_verify_ifscope(&sin6->sin6_addr, sin6->sin6_scope_id);
				if (islocalUpdate) {
					entry->soflow_laddr_updated = TRUE;
				}
			}
		} else {
			if (sin6->sin6_port != 0) {
				entry->soflow_fport = sin6->sin6_port;
			}
			if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				entry->soflow_faddr.addr6 = sin6->sin6_addr;
				entry->soflow_faddr6_ifscope = sin6->sin6_scope_id;
				in6_verify_ifscope(&sin6->sin6_addr, sin6->sin6_scope_id);
			}
		}
		entry->soflow_family = AF_INET6;
		return TRUE;
	default:
		return FALSE;
	}
}

bool
soflow_fill_hash_entry_from_inp(struct soflow_hash_entry *entry, bool isLocal, struct inpcb *inp, bool islocalUpdate)
{
	if (entry == NULL || inp == NULL) {
		return FALSE;
	}

	if (inp->inp_vflag & INP_IPV6) {
		if (isLocal == TRUE) {
			if (inp->inp_lport) {
				entry->soflow_lport = inp->inp_lport;
				if (islocalUpdate) {
					entry->soflow_lport_updated = TRUE;
				}
			}
			if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
				entry->soflow_laddr.addr6 = inp->in6p_laddr;
				entry->soflow_laddr6_ifscope = inp->inp_lifscope;
				in6_verify_ifscope(&entry->soflow_laddr.addr6, inp->inp_lifscope);
				if (islocalUpdate) {
					entry->soflow_laddr_updated = TRUE;
				}
			}
		} else {
			if (inp->inp_fport) {
				entry->soflow_fport = inp->inp_fport;
			}
			if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
				entry->soflow_faddr.addr6 = inp->in6p_faddr;
				entry->soflow_faddr6_ifscope = inp->inp_fifscope;
				in6_verify_ifscope(&entry->soflow_faddr.addr6, inp->inp_fifscope);
			}
		}
		entry->soflow_family = AF_INET6;
		return TRUE;
	} else if (inp->inp_vflag & INP_IPV4) {
		if (isLocal == TRUE) {
			if (inp->inp_lport) {
				entry->soflow_lport = inp->inp_lport;
				if (islocalUpdate) {
					entry->soflow_lport_updated = TRUE;
				}
			}
			if (inp->inp_laddr.s_addr) {
				entry->soflow_laddr.addr46.ia46_addr4.s_addr = inp->inp_laddr.s_addr;
				if (islocalUpdate) {
					entry->soflow_laddr_updated = TRUE;
				}
			}
		} else {
			if (inp->inp_fport) {
				entry->soflow_fport = inp->inp_fport;
			}
			if (inp->inp_faddr.s_addr) {
				entry->soflow_faddr.addr46.ia46_addr4.s_addr = inp->inp_faddr.s_addr;
			}
		}
		entry->soflow_family = AF_INET;
		return TRUE;
	}
	return FALSE;
}

static errno_t
soflow_db_init(struct socket *so)
{
	errno_t error = 0;
	struct soflow_db *db = NULL;
	struct soflow_hash_entry *hash_entry = NULL;

	db = kalloc_type(struct soflow_db, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	db->soflow_db_so = so;
	db->soflow_db_hashbase = hashinit(SOFLOW_HASH_SIZE, M_CFIL, &db->soflow_db_hashmask);
	if (db->soflow_db_hashbase == NULL) {
		kfree_type(struct soflow_db, db);
		error = ENOMEM;
		goto done;
	}
	db->soflow_db_debug = SOFLOW_ENABLE_DEBUG(so, hash_entry);
	os_ref_init(&db->soflow_db_ref_count, &soflow_refgrp);
	so->so_flow_db = db;
done:
	return error;
}

static void
soflow_entry_free(struct soflow_hash_entry *hash_entry)
{
	struct socket *so = (hash_entry && hash_entry->soflow_db) ? hash_entry->soflow_db->soflow_db_so : NULL;

	if (hash_entry == NULL) {
		return;
	}

	SOFLOW_ENTRY_LOG(LOG_INFO, so, hash_entry, hash_entry->soflow_debug, "Free entry");
	kfree_type(struct soflow_hash_entry, hash_entry);
}

static void
soflow_db_remove_entry(struct soflow_db *db, struct soflow_hash_entry *hash_entry)
{
	if (hash_entry == NULL) {
		return;
	}
	if (db == NULL || db->soflow_db_count == 0) {
		return;
	}


	db->soflow_db_count--;
	if (db->soflow_db_only_entry == hash_entry) {
		db->soflow_db_only_entry = NULL;
	}
	LIST_REMOVE(hash_entry, soflow_entry_link);

	// Feature context present, give feature a chance to detach and clean up
	if (hash_entry->soflow_feat_ctxt != NULL && soflow_feat_detach_entry_func_ptr != NULL) {
		soflow_feat_detach_entry_func_ptr(db->soflow_db_so, hash_entry);
		hash_entry->soflow_feat_ctxt = NULL;
		hash_entry->soflow_feat_ctxt_id = 0;
	}

	hash_entry->soflow_db = NULL;

	SOFLOW_LOCK_EXCLUSIVE;
	if (soflow_initialized) {
		TAILQ_REMOVE(&soflow_entry_head, hash_entry, soflow_entry_list_link);
		soflow_attached_count--;
	}
	SOFLOW_UNLOCK_EXCLUSIVE;

	SOFLOW_ENTRY_FREE(hash_entry);
}

static void
soflow_db_free(struct soflow_db *db)
{
	struct soflow_hash_entry *entry = NULL;
	struct soflow_hash_entry *temp_entry = NULL;
	struct soflow_hash_head *flowhash = NULL;

	if (db == NULL) {
		return;
	}

	SOFLOW_LOG(LOG_INFO, db->soflow_db_so, db->soflow_db_debug, "<db %p> freeing db (count == %d)", db, db->soflow_db_count);

	for (int i = 0; i < SOFLOW_HASH_SIZE; i++) {
		flowhash = &db->soflow_db_hashbase[i];
		LIST_FOREACH_SAFE(entry, flowhash, soflow_entry_link, temp_entry) {
			SOFLOW_ENTRY_LOG(LOG_INFO, db->soflow_db_so, entry, entry->soflow_debug, "Remove entry");
			soflow_db_remove_entry(db, entry);
		}
	}

	if (soflow_feat_detach_db_func_ptr != NULL) {
		soflow_feat_detach_db_func_ptr(db->soflow_db_so, db);
	}

	// Make sure all entries are cleaned up!
	VERIFY(db->soflow_db_count == 0);
	hashdestroy(db->soflow_db_hashbase, M_CFIL, db->soflow_db_hashmask);
	kfree_type(struct soflow_db, db);
}

void
soflow_detach(struct socket *so)
{
	if (so == NULL || so->so_flow_db == NULL) {
		return;
	}
	SOFLOW_DB_FREE(so->so_flow_db);
	so->so_flow_db = NULL;
}

static boolean_t
soflow_match_entries_v4(struct soflow_hash_entry *entry1, struct soflow_hash_entry *entry2, boolean_t remoteOnly)
{
	if (entry1 == NULL || entry2 == NULL) {
		return false;
	}

	// Ignore local match if remoteOnly or if local has been updated since entry added
	boolean_t lport_matched = (remoteOnly || entry1->soflow_lport_updated || entry1->soflow_lport == entry2->soflow_lport);
	boolean_t laddr_matched = (remoteOnly || entry1->soflow_laddr_updated ||
	    entry1->soflow_laddr.addr46.ia46_addr4.s_addr == entry2->soflow_laddr.addr46.ia46_addr4.s_addr);

	// Entries match if local and remote ports and addresses all matched
	return lport_matched && entry1->soflow_fport == entry2->soflow_fport &&
	       laddr_matched && entry1->soflow_faddr.addr46.ia46_addr4.s_addr == entry2->soflow_faddr.addr46.ia46_addr4.s_addr;
}

static boolean_t
soflow_match_entries_v6(struct soflow_hash_entry *entry1, struct soflow_hash_entry *entry2, boolean_t remoteOnly)
{
	if (entry1 == NULL || entry2 == NULL) {
		return false;
	}

	// Ignore local match if remoteOnly or if local has been updated since entry added
	boolean_t lport_matched = (remoteOnly || entry1->soflow_lport_updated || entry1->soflow_lport == entry2->soflow_lport);
	boolean_t laddr_matched = (remoteOnly || entry1->soflow_laddr_updated ||
	    in6_are_addr_equal_scoped(&entry1->soflow_laddr.addr6, &entry2->soflow_laddr.addr6, entry1->soflow_laddr6_ifscope, entry2->soflow_laddr6_ifscope));

	// Entries match if local and remote ports and addresses all matched
	return lport_matched && entry1->soflow_fport == entry2->soflow_fport &&
	       laddr_matched && in6_are_addr_equal_scoped(&entry1->soflow_faddr.addr6, &entry2->soflow_faddr.addr6, entry1->soflow_faddr6_ifscope, entry2->soflow_faddr6_ifscope);
}

static struct soflow_hash_entry *
soflow_db_lookup_entry_internal(struct soflow_db *db, struct sockaddr *local, struct sockaddr *remote, boolean_t remoteOnly, boolean_t withLocalPort)
{
	struct soflow_hash_entry matchentry = { };
	struct soflow_hash_entry *nextentry = NULL;
	struct inpcb *inp = sotoinpcb(db->soflow_db_so);
	u_int32_t hashkey_faddr = 0, hashkey_laddr = 0;
	u_int16_t hashkey_fport = 0, hashkey_lport = 0;
	int inp_hash_element = 0;
	struct soflow_hash_head *flowhash = NULL;

	if (inp == NULL || db == NULL) {
		return NULL;
	}

	if (local != NULL) {
		soflow_fill_hash_entry_from_address(&matchentry, TRUE, local, FALSE);
	} else {
		soflow_fill_hash_entry_from_inp(&matchentry, TRUE, inp, FALSE);
	}
	if (remote != NULL) {
		soflow_fill_hash_entry_from_address(&matchentry, FALSE, remote, FALSE);
	} else {
		soflow_fill_hash_entry_from_inp(&matchentry, FALSE, inp, FALSE);
	}
	matchentry.soflow_debug = SOFLOW_ENABLE_DEBUG(db->soflow_db_so, (&matchentry));
	SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, &matchentry, true, "Looking for entry");

	if (inp->inp_vflag & INP_IPV6) {
		hashkey_faddr = matchentry.soflow_faddr.addr6.s6_addr32[3];
		hashkey_laddr = (remoteOnly == false) ? matchentry.soflow_laddr.addr6.s6_addr32[3] : 0;
	} else {
		hashkey_faddr = matchentry.soflow_faddr.addr46.ia46_addr4.s_addr;
		hashkey_laddr = (remoteOnly == false) ? matchentry.soflow_laddr.addr46.ia46_addr4.s_addr : 0;
	}

	hashkey_fport = matchentry.soflow_fport;
	hashkey_lport = (remoteOnly == false || withLocalPort == true) ? matchentry.soflow_lport : 0;

	inp_hash_element = SOFLOW_HASH(hashkey_laddr, hashkey_faddr, hashkey_lport, hashkey_fport);
	inp_hash_element &= db->soflow_db_hashmask;
	flowhash = &db->soflow_db_hashbase[inp_hash_element];

	LIST_FOREACH(nextentry, flowhash, soflow_entry_link) {
		if (inp->inp_vflag & INP_IPV6) {
			if (soflow_match_entries_v6(nextentry, &matchentry, remoteOnly)) {
				SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, nextentry, nextentry->soflow_debug, "Found entry v6");
				break;
			}
		} else if (inp->inp_vflag & INP_IPV4) {
			if (soflow_match_entries_v4(nextentry, &matchentry, remoteOnly)) {
				SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, nextentry, nextentry->soflow_debug, "Found entry v4");
				break;
			}
		}
	}

	if (nextentry == NULL) {
		SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, &matchentry, matchentry.soflow_debug, "Entry not found");
	}
	return nextentry;
}

static struct soflow_hash_entry *
soflow_db_lookup_entry(struct soflow_db *db, struct sockaddr *local, struct sockaddr *remote, boolean_t remoteOnly)
{
	struct soflow_hash_entry *entry = soflow_db_lookup_entry_internal(db, local, remote, remoteOnly, false);
	if (entry == NULL && remoteOnly == true) {
		entry = soflow_db_lookup_entry_internal(db, local, remote, remoteOnly, true);
	}
	return entry;
}

static struct soflow_hash_entry *
soflow_db_lookup_by_feature_context_id(struct soflow_db *db, u_int64_t feature_context_id)
{
	struct soflow_hash_head *flowhash = NULL;
	u_int32_t inp_hash_element = (u_int32_t)(feature_context_id & 0x0ffffffff);
	struct soflow_hash_entry *nextentry;

	inp_hash_element &= db->soflow_db_hashmask;
	flowhash = &db->soflow_db_hashbase[inp_hash_element];

	LIST_FOREACH(nextentry, flowhash, soflow_entry_link) {
		SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, nextentry, nextentry->soflow_debug, "Looking at entry");
		if (nextentry->soflow_feat_ctxt != NULL &&
		    nextentry->soflow_feat_ctxt_id == feature_context_id) {
			SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, nextentry, nextentry->soflow_debug, "Found entry by feature context id");
			break;
		}
	}

	if (nextentry == NULL) {
		SOFLOW_LOG(LOG_DEBUG, db->soflow_db_so, db->soflow_db_debug, "No entry found for featureID %llu <count %d hash %X %X>",
		    feature_context_id, db->soflow_db_count, inp_hash_element, (u_int32_t)(feature_context_id & 0x0ffffffff));
	}
	return nextentry;
}

void *
soflow_db_get_feature_context(struct soflow_db *db, u_int64_t feature_context_id)
{
	struct soflow_hash_entry *hash_entry = NULL;
	void *context = NULL;

	if (db == NULL || db->soflow_db_so == NULL || feature_context_id == 0) {
		return NULL;
	}

	socket_lock_assert_owned(db->soflow_db_so);

	// Take refcount of db before use.
	// Abort if db is already being freed.
	if (os_ref_retain_try(&db->soflow_db_ref_count) == false) {
		return NULL;
	}

	// This is an optimization for datagram sockets with only one single flow.
	if (db->soflow_db_count == 1) {
		if (db->soflow_db_only_entry != NULL &&
		    db->soflow_db_only_entry->soflow_feat_ctxt != NULL && db->soflow_db_only_entry->soflow_feat_ctxt_id == feature_context_id) {
			SOFLOW_ENTRY_LOG(LOG_DEBUG, db->soflow_db_so, db->soflow_db_only_entry, db->soflow_db_only_entry->soflow_debug, "MATCHED only entry for featureID");
			context = db->soflow_db_only_entry->soflow_feat_ctxt;
		} else {
			SOFLOW_LOG(LOG_DEBUG, db->soflow_db_so, db->soflow_db_debug, "MISMATCHED only entry for featureID %llu (entry %p - cfil %p id %llu)",
			    feature_context_id,
			    db->soflow_db_only_entry,
			    db->soflow_db_only_entry ? db->soflow_db_only_entry->soflow_feat_ctxt : NULL,
			    db->soflow_db_only_entry ? db->soflow_db_only_entry->soflow_feat_ctxt_id : 0);
		}
	} else {
		hash_entry = soflow_db_lookup_by_feature_context_id(db, feature_context_id);
		context = hash_entry != NULL ? hash_entry->soflow_feat_ctxt : NULL;
	}

	SOFLOW_DB_FREE(db);
	return context;
}

u_int64_t
soflow_db_get_feature_context_id(struct soflow_db *db, struct sockaddr *local, struct sockaddr *remote)
{
	struct soflow_hash_entry *hash_entry = NULL;
	uint64_t context_id = 0;

	if (db == NULL || db->soflow_db_so == NULL) {
		return 0;
	}

	socket_lock_assert_owned(db->soflow_db_so);

	// Take refcount of db before use.
	// Abort if db is already being freed.
	if (os_ref_retain_try(&db->soflow_db_ref_count) == false) {
		return 0;
	}

	hash_entry = soflow_db_lookup_entry(db, local, remote, false);
	if (hash_entry == NULL) {
		// No match with both local and remote, try match with remote only
		hash_entry = soflow_db_lookup_entry(db, local, remote, true);
	}
	if (hash_entry != NULL && hash_entry->soflow_feat_ctxt != NULL) {
		context_id = hash_entry->soflow_feat_ctxt_id;
	}

	SOFLOW_DB_FREE(db);

	return context_id;
}

static struct soflow_hash_entry *
soflow_db_add_entry(struct soflow_db *db, struct sockaddr *local, struct sockaddr *remote)
{
	struct soflow_hash_entry *entry = NULL;
	struct inpcb *inp = db ? sotoinpcb(db->soflow_db_so) : NULL;
	u_int32_t hashkey_faddr = 0, hashkey_laddr = 0;
	int inp_hash_element = 0;
	struct soflow_hash_head *flowhash = NULL;

	if (db == NULL || inp == NULL) {
		goto done;
	}

	entry = kalloc_type(struct soflow_hash_entry, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	os_ref_init(&entry->soflow_ref_count, &soflow_refgrp);

	if (local != NULL) {
		soflow_fill_hash_entry_from_address(entry, TRUE, local, FALSE);
	} else {
		soflow_fill_hash_entry_from_inp(entry, TRUE, inp, FALSE);
	}
	if (remote != NULL) {
		soflow_fill_hash_entry_from_address(entry, FALSE, remote, FALSE);
	} else {
		soflow_fill_hash_entry_from_inp(entry, FALSE, inp, FALSE);
	}
	entry->soflow_lastused = net_uptime();
	entry->soflow_db = db;
	entry->soflow_debug = SOFLOW_ENABLE_DEBUG(db->soflow_db_so, entry);

	if (inp->inp_vflag & INP_IPV6) {
		hashkey_faddr = entry->soflow_faddr.addr6.s6_addr32[3];
		hashkey_laddr = entry->soflow_laddr.addr6.s6_addr32[3];
	} else {
		hashkey_faddr = entry->soflow_faddr.addr46.ia46_addr4.s_addr;
		hashkey_laddr = entry->soflow_laddr.addr46.ia46_addr4.s_addr;
	}
	entry->soflow_flowhash = SOFLOW_HASH(hashkey_laddr, hashkey_faddr,
	    entry->soflow_lport, entry->soflow_fport);
	inp_hash_element = entry->soflow_flowhash & db->soflow_db_hashmask;

	socket_lock_assert_owned(db->soflow_db_so);

	// Take refcount of db before use.
	// Abort if db is already being freed.
	if (os_ref_retain_try(&db->soflow_db_ref_count) == false) {
		return NULL;
	}

	flowhash = &db->soflow_db_hashbase[inp_hash_element];

	LIST_INSERT_HEAD(flowhash, entry, soflow_entry_link);
	db->soflow_db_count++;
	db->soflow_db_only_entry = entry;
	SOFLOW_LOG(LOG_INFO, db->soflow_db_so, db->soflow_db_debug, "total count %d", db->soflow_db_count);

	SOFLOW_DB_FREE(db);

done:
	return entry;
}

static int
soflow_udp_get_address_from_control(sa_family_t family, struct mbuf *control, uint8_t **address_ptr)
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi6;
	struct socket *so = NULL;

	if (control == NULL || address_ptr == NULL) {
		return 0;
	}

	for (; control != NULL; control = control->m_next) {
		if (control->m_type != MT_CONTROL) {
			continue;
		}

		for (cm = M_FIRST_CMSGHDR(control);
		    is_cmsg_valid(control, cm);
		    cm = M_NXT_CMSGHDR(control, cm)) {
			SOFLOW_LOG(LOG_DEBUG, so, true, "Check control type %d", cm->cmsg_type);

			switch (cm->cmsg_type) {
			case IP_RECVDSTADDR:
				if (family == AF_INET &&
				    cm->cmsg_level == IPPROTO_IP &&
				    cm->cmsg_len == CMSG_LEN(sizeof(struct in_addr))) {
					*address_ptr = CMSG_DATA(cm);
					return sizeof(struct in_addr);
				}
				break;
			case IPV6_PKTINFO:
			case IPV6_2292PKTINFO:
				if (family == AF_INET6 &&
				    cm->cmsg_level == IPPROTO_IPV6 &&
				    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
					pi6 = (struct in6_pktinfo *)(void *)CMSG_DATA(cm);
					*address_ptr = (uint8_t *)&pi6->ipi6_addr;
					return sizeof(struct in6_addr);
				}
				break;
			default:
				break;
			}
		}
	}
	return 0;
}

static boolean_t
soflow_entry_local_address_needs_update(struct soflow_hash_entry *entry)
{
	if (entry->soflow_family == AF_INET6) {
		return IN6_IS_ADDR_UNSPECIFIED(&entry->soflow_laddr.addr6);
	} else if (entry->soflow_family == AF_INET) {
		return entry->soflow_laddr.addr46.ia46_addr4.s_addr == INADDR_ANY;
	}
	return false;
}

static boolean_t
soflow_entry_local_port_needs_update(struct socket *so, struct soflow_hash_entry *entry)
{
	if (SOFLOW_IS_UDP(so)) {
		return entry->soflow_lport == 0;
	}
	return false;
}

static void
soflow_entry_update_local(struct soflow_db *db, struct soflow_hash_entry *entry, struct sockaddr *local, struct mbuf *control, u_short rcv_ifindex)
{
	struct inpcb *inp = sotoinpcb(db->soflow_db_so);
	union sockaddr_in_4_6 address_buf = { };

	if (inp == NULL || entry == NULL) {
		return;
	}

	if (entry->soflow_outifindex == 0 && (inp->inp_last_outifp != NULL || rcv_ifindex != 0)) {
		entry->soflow_outifindex = inp->inp_last_outifp ? inp->inp_last_outifp->if_index : rcv_ifindex;
		SOFLOW_ENTRY_LOG(LOG_INFO, db->soflow_db_so, entry, entry->soflow_debug, "Updated outifp");
	}

	if (soflow_entry_local_address_needs_update(entry)) {
		// Flow does not have a local address yet.  Retrieve local address
		// from control mbufs if present.
		if (local == NULL && control != NULL) {
			uint8_t *addr_ptr = NULL;
			int size = soflow_udp_get_address_from_control(entry->soflow_family, control, &addr_ptr);

			if (size && addr_ptr) {
				switch (entry->soflow_family) {
				case AF_INET:
					if (size == sizeof(struct in_addr)) {
						address_buf.sin.sin_port = 0;
						address_buf.sin.sin_family = AF_INET;
						address_buf.sin.sin_len = sizeof(struct sockaddr_in);
						(void) memcpy(&address_buf.sin.sin_addr, addr_ptr, sizeof(struct in_addr));
						local = sintosa(&address_buf.sin);
					}
					break;
				case AF_INET6:
					if (size == sizeof(struct in6_addr)) {
						address_buf.sin6.sin6_port = 0;
						address_buf.sin6.sin6_family = AF_INET6;
						address_buf.sin6.sin6_len = sizeof(struct sockaddr_in6);
						(void) memcpy(&address_buf.sin6.sin6_addr, addr_ptr, sizeof(struct in6_addr));
						local = sin6tosa(&address_buf.sin6);
					}
					break;
				default:
					break;
				}
			}
		}
		if (local != NULL) {
			soflow_fill_hash_entry_from_address(entry, TRUE, local, TRUE);
		} else {
			soflow_fill_hash_entry_from_inp(entry, TRUE, inp, TRUE);
		}
		if (entry->soflow_laddr_updated) {
			SOFLOW_ENTRY_LOG(LOG_INFO, db->soflow_db_so, entry, entry->soflow_debug, "Updated address");
		}
	}

	if (soflow_entry_local_port_needs_update(db->soflow_db_so, entry)) {
		soflow_fill_hash_entry_from_inp(entry, TRUE, inp, TRUE);
		if (entry->soflow_lport_updated) {
			SOFLOW_ENTRY_LOG(LOG_INFO, db->soflow_db_so, entry, entry->soflow_debug, "Updated port");
		}
	}

	return;
}


static void
soflow_update_flow_stats(struct soflow_hash_entry *hash_entry, size_t data_size, bool outgoing)
{
	struct socket *so = (hash_entry && hash_entry->soflow_db) ? hash_entry->soflow_db->soflow_db_so : NULL;

	if (hash_entry != NULL) {
		if (outgoing) {
			hash_entry->soflow_txbytes += data_size;
			hash_entry->soflow_txpackets++;
			SOFLOW_ENTRY_LOG(LOG_DEBUG, so, hash_entry, hash_entry->soflow_debug, "Stats update - Outgoing");
		} else {
			hash_entry->soflow_rxbytes += data_size;
			hash_entry->soflow_rxpackets++;
			SOFLOW_ENTRY_LOG(LOG_DEBUG, so, hash_entry, hash_entry->soflow_debug, "Stats update - Incoming");
		}
	}
}

struct soflow_hash_entry *
soflow_get_flow(struct socket *so, struct sockaddr *local, struct sockaddr *remote, struct mbuf *control,
    size_t data_size, bool outgoing, uint16_t rcv_ifindex)
{
	struct soflow_hash_entry *hash_entry = NULL;
	struct inpcb *inp = sotoinpcb(so);

	// Check if feature is disabled
	if (soflow_disable) {
		return NULL;
	}

	socket_lock_assert_owned(so);

	if (so->so_flow_db != NULL) {
		// Take refcount of db before use.
		// Abort if db is already being freed.
		if (os_ref_retain_try(&so->so_flow_db->soflow_db_ref_count) == false) {
			return NULL;
		}

		// DB already exists, check if this is existing flow
		hash_entry = soflow_db_lookup_entry(so->so_flow_db, local, remote, false);
		if (hash_entry == NULL) {
			// No match with both local and remote, try match with remote only
			hash_entry = soflow_db_lookup_entry(so->so_flow_db, local, remote, true);
		}
		if (hash_entry != NULL) {
			// Take refcount of entry before use.
			// Abort if entry is already being freed.
			if (os_ref_retain_try(&hash_entry->soflow_ref_count) == false) {
				SOFLOW_DB_FREE(so->so_flow_db);
				return NULL;
			}

			// Try to update flow info from socket and/or control mbufs if necessary
			if (hash_entry->soflow_outifindex == 0 ||
			    soflow_entry_local_address_needs_update(hash_entry) || soflow_entry_local_port_needs_update(so, hash_entry)) {
				soflow_entry_update_local(so->so_flow_db, hash_entry, local, control, rcv_ifindex);
			}
			hash_entry->soflow_lastused = net_uptime();
			soflow_update_flow_stats(hash_entry, data_size, outgoing);

			SOFLOW_DB_FREE(so->so_flow_db);
			return hash_entry;
		}

		SOFLOW_DB_FREE(so->so_flow_db);
	} else {
		// If new socket, allocate cfil db
		if (soflow_db_init(so) != 0) {
			return NULL;
		}
	}

	hash_entry = soflow_db_add_entry(so->so_flow_db, local, remote);
	if (hash_entry == NULL) {
		SOFLOW_LOG(LOG_ERR, so, true, "Failed to add entry");
		return NULL;
	}

	// Take refcount of entry before use.
	// Abort if entry is already being freed.
	if (os_ref_retain_try(&hash_entry->soflow_ref_count) == false) {
		return NULL;
	}

	if (inp && (inp->inp_last_outifp != NULL || rcv_ifindex != 0)) {
		hash_entry->soflow_outifindex = inp->inp_last_outifp ? inp->inp_last_outifp->if_index : rcv_ifindex;
	}

	// Check if we can update the new flow's local address from control mbufs
	if (control != NULL) {
		soflow_entry_update_local(so->so_flow_db, hash_entry, local, control, rcv_ifindex);
	}
	hash_entry->soflow_outgoing = outgoing;
	soflow_update_flow_stats(hash_entry, data_size, outgoing);

	// Only report flow to NSTAT if unconnected UDP
	if (!soflow_nstat_disable && SOFLOW_IS_UDP(so) && !(so->so_state & (SS_ISCONNECTED | SS_ISCONNECTING))) {
	}

	SOFLOW_LOCK_EXCLUSIVE;
	if (soflow_initialized == 0) {
		soflow_init();
	}
	TAILQ_INSERT_TAIL(&soflow_entry_head, hash_entry, soflow_entry_list_link);
	if (soflow_attached_count == 0) {
		thread_wakeup((caddr_t)&soflow_attached_count);
	}
	soflow_attached_count++;
	SOFLOW_UNLOCK_EXCLUSIVE;

	SOFLOW_ENTRY_LOG(LOG_INFO, so, hash_entry, hash_entry->soflow_debug, "Added entry");
	return hash_entry;
}

void
soflow_free_flow(struct soflow_hash_entry *entry)
{
	SOFLOW_ENTRY_FREE(entry);
}

static bool
soflow_socket_safe_lock(struct inpcb *inp, struct inpcbinfo *pcbinfo)
{
	struct socket *so = NULL;

	VERIFY(pcbinfo != NULL);

	if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
		// Safeguarded the inp state, unlock pcbinfo before locking socket.
		lck_rw_done(&pcbinfo->ipi_lock);

		so = inp->inp_socket;
		socket_lock(so, 1);
		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) != WNT_STOPUSING) {
			return true;
		}
	} else {
		// Failed to safeguarded the inp state, unlock pcbinfo and abort.
		lck_rw_done(&pcbinfo->ipi_lock);
	}

	if (so) {
		socket_unlock(so, 1);
	}
	return false;
}

static struct socket *
soflow_validate_dgram_socket(struct socket *so)
{
	struct inpcb *inp = NULL;
	struct inpcbinfo *pcbinfo = NULL;
	struct socket *locked = NULL;

	pcbinfo = &udbinfo;
	lck_rw_lock_shared(&pcbinfo->ipi_lock);
	LIST_FOREACH(inp, pcbinfo->ipi_listhead, inp_list) {
		if (inp->inp_state != INPCB_STATE_DEAD && inp->inp_socket == so) {
			if (soflow_socket_safe_lock(inp, pcbinfo)) {
				locked = inp->inp_socket;
			}
			/* pcbinfo is already unlocked, we are done. */
			goto done;
		}
	}
	lck_rw_done(&pcbinfo->ipi_lock);
	if (locked != NULL) {
		goto done;
	}

	pcbinfo = &ripcbinfo;
	lck_rw_lock_shared(&pcbinfo->ipi_lock);
	LIST_FOREACH(inp, pcbinfo->ipi_listhead, inp_list) {
		if (inp->inp_state != INPCB_STATE_DEAD && inp->inp_socket == so) {
			if (soflow_socket_safe_lock(inp, pcbinfo)) {
				locked = inp->inp_socket;
			}
			/* pcbinfo is already unlocked, we are done. */
			goto done;
		}
	}
	lck_rw_done(&pcbinfo->ipi_lock);

done:
	return locked;
}

static void
soflow_gc_thread_sleep(bool forever)
{
	if (forever) {
		(void) assert_wait((event_t) &soflow_attached_count,
		    THREAD_INTERRUPTIBLE);
	} else {
		uint64_t deadline = 0;
		nanoseconds_to_absolutetime(SOFLOW_GC_RUN_INTERVAL_NSEC, &deadline);
		clock_absolutetime_interval_to_deadline(deadline, &deadline);

		(void) assert_wait_deadline(&soflow_attached_count,
		    THREAD_INTERRUPTIBLE, deadline);
	}
}

static void
soflow_gc_thread_func(void *v, wait_result_t w)
{
#pragma unused(v, w)

	ASSERT(soflow_gc_thread == current_thread());
	thread_set_thread_name(current_thread(), "SOFLOW_GC");

	// Kick off gc shortly
	soflow_gc_thread_sleep(false);
	thread_block_parameter((thread_continue_t) soflow_gc_expire, NULL);
	/* NOTREACHED */
}

static bool
soflow_gc_idle_timed_out(struct soflow_hash_entry *hash_entry, int timeout, u_int64_t current_time)
{
	struct socket *so = (hash_entry && hash_entry->soflow_db) ? hash_entry->soflow_db->soflow_db_so : NULL;

	if (hash_entry && (current_time - hash_entry->soflow_lastused >= (u_int64_t)timeout)) {
		SOFLOW_ENTRY_LOG(LOG_INFO, so, hash_entry, hash_entry->soflow_debug, "GC Idle Timeout detected");
		return true;
	}
	return false;
}

static int
soflow_gc_cleanup(struct socket *so)
{
	struct soflow_hash_entry *entry = NULL;
	struct soflow_hash_entry *temp_entry = NULL;
	struct soflow_hash_head *flowhash = NULL;
	struct soflow_db *db = NULL;
	int cleaned = 0;

	if (so == NULL || so->so_flow_db == NULL) {
		return 0;
	}
	db = so->so_flow_db;

	socket_lock_assert_owned(so);

	// Take refcount of db before use.
	// Abort if db is already being freed.
	if (os_ref_retain_try(&db->soflow_db_ref_count) == false) {
		return 0;
	}

	for (int i = 0; i < SOFLOW_HASH_SIZE; i++) {
		flowhash = &db->soflow_db_hashbase[i];
		LIST_FOREACH_SAFE(entry, flowhash, soflow_entry_link, temp_entry) {
			if (entry->soflow_gc || entry->soflow_feat_gc) {
				if (entry->soflow_feat_ctxt != NULL && soflow_feat_gc_perform_func_ptr != NULL) {
					soflow_feat_gc_perform_func_ptr(so, entry);
					entry->soflow_feat_ctxt = NULL;
					entry->soflow_feat_ctxt_id = 0;
				}
				entry->soflow_feat_gc = 0;

				if (entry->soflow_gc) {
					SOFLOW_ENTRY_LOG(LOG_INFO, so, entry, entry->soflow_debug, "GC cleanup entry");
					entry->soflow_gc = 0;
					soflow_db_remove_entry(db, entry);
					cleaned++;
				}
			}
		}
	}

	SOFLOW_DB_FREE(db);
	return cleaned;
}

static void
soflow_gc_expire(void *v, wait_result_t w)
{
#pragma unused(v, w)

	static struct socket *socket_array[SOFLOW_GC_MAX_COUNT];
	struct soflow_hash_entry *hash_entry = NULL;
	struct socket *so = NULL;
	u_int64_t current_time = net_uptime();
	uint32_t socket_count = 0;
	uint32_t cleaned_count = 0;
	bool recorded = false;

	// Collect a list of socket with expired flows

	SOFLOW_LOCK_SHARED;

	if (soflow_attached_count == 0) {
		SOFLOW_UNLOCK_SHARED;
		goto go_sleep;
	}

	// Go thorough all flows in the flow list and record any socket with expired flows.
	TAILQ_FOREACH(hash_entry, &soflow_entry_head, soflow_entry_list_link) {
		if (socket_count >= SOFLOW_GC_MAX_COUNT) {
			break;
		}
		so = hash_entry->soflow_db ? hash_entry->soflow_db->soflow_db_so : NULL;

		// Check if we need to perform cleanup due to idle time or feature specified rules
		hash_entry->soflow_gc = soflow_gc_idle_timed_out(hash_entry, SOFLOW_GC_IDLE_TO, current_time);
		hash_entry->soflow_feat_gc = (soflow_feat_gc_needed_func_ptr != NULL && soflow_feat_gc_needed_func_ptr(so, hash_entry, current_time));

		if (hash_entry->soflow_gc || hash_entry->soflow_feat_gc) {
			if (so != NULL) {
				recorded = false;
				for (int i = 0; i < socket_count; i++) {
					if (socket_array[socket_count] == so) {
						recorded = true;
						break;
					}
				}
				if (recorded == false) {
					socket_array[socket_count] = so;
					socket_count++;
				}
			}
		}
	}
	SOFLOW_UNLOCK_SHARED;

	if (socket_count == 0) {
		goto go_sleep;
	}

	for (uint32_t i = 0; i < socket_count; i++) {
		// Validate socket and lock it
		so = soflow_validate_dgram_socket(socket_array[i]);
		if (so == NULL) {
			continue;
		}
		cleaned_count += soflow_gc_cleanup(so);
		socket_unlock(so, 1);
	}

	so = NULL;
	SOFLOW_LOG(LOG_INFO, so, true, "<GC cleaned %d flows>", cleaned_count);

go_sleep:

	// Sleep forever (until waken up) if no more UDP flow to clean
	SOFLOW_LOCK_SHARED;
	soflow_gc_thread_sleep(soflow_attached_count == 0 ? true : false);
	SOFLOW_UNLOCK_SHARED;
	thread_block_parameter((thread_continue_t)soflow_gc_expire, NULL);
	/* NOTREACHED */
}

void
soflow_feat_set_functions(soflow_feat_gc_needed_func gc_needed_fn,
    soflow_feat_gc_perform_func gc_perform_fn,
    soflow_feat_detach_entry_func feat_detach_entry_fn,
    soflow_feat_detach_db_func feat_detach_db_fn)
{
	soflow_feat_gc_needed_func_ptr = gc_needed_fn;
	soflow_feat_gc_perform_func_ptr = gc_perform_fn;
	soflow_feat_detach_entry_func_ptr = feat_detach_entry_fn;
	soflow_feat_detach_db_func_ptr = feat_detach_db_fn;
}

bool
soflow_db_apply(struct soflow_db *db, soflow_entry_apply_func entry_apply_fn, void *context)
{
	struct soflow_hash_entry *entry = NULL;
	struct soflow_hash_entry *temp_entry = NULL;
	struct soflow_hash_head *flowhash = NULL;

	if (db == NULL || db->soflow_db_so == NULL || entry_apply_fn == NULL) {
		return false;
	}

	socket_lock_assert_owned(db->soflow_db_so);

	// Take refcount of db before use.
	// Abort if db is already being freed.
	if (os_ref_retain_try(&db->soflow_db_ref_count) == false) {
		return false;
	}

	for (int i = 0; i < SOFLOW_HASH_SIZE; i++) {
		flowhash = &db->soflow_db_hashbase[i];
		LIST_FOREACH_SAFE(entry, flowhash, soflow_entry_link, temp_entry) {
			if (entry_apply_fn(db->soflow_db_so, entry, context) == false) {
				goto done;
			}
		}
	}

done:
	SOFLOW_DB_FREE(db);
	return true;
}
