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

#ifndef __SOCKET_FLOWS_H__
#define __SOCKET_FLOWS_H__


__BEGIN_DECLS

#ifdef PRIVATE

struct soflow_hash_entry {
	LIST_ENTRY(soflow_hash_entry)       soflow_entry_link;
	TAILQ_ENTRY(soflow_hash_entry)      soflow_entry_list_link;
	os_refcnt_t                         soflow_ref_count;
	struct soflow_db                    *soflow_db;
	uint16_t                            soflow_outifindex;
	in_port_t                           soflow_fport;
	in_port_t                           soflow_lport;
	sa_family_t                         soflow_family;
	uint32_t                            soflow_flowhash;
	uint64_t                            soflow_lastused;
	uint32_t                            soflow_faddr6_ifscope;
	uint32_t                            soflow_laddr6_ifscope;
	union {
		/* foreign host table entry */
		struct in_addr_4in6             addr46;
		struct in6_addr                 addr6;
	} soflow_faddr;
	union {
		/* local host table entry */
		struct in_addr_4in6             addr46;
		struct in6_addr                 addr6;
	} soflow_laddr;
	uint8_t                             soflow_outgoing: 1;
	uint8_t                             soflow_laddr_updated: 1;
	uint8_t                             soflow_lport_updated: 1;
	uint8_t                             soflow_gc: 1;
	uint8_t                             soflow_feat_gc: 1;
	uint8_t                             soflow_debug: 1;
	uint8_t                             soflow_reserved:2;

	uint64_t                            soflow_rxpackets;
	uint64_t                            soflow_rxbytes;
	uint64_t                            soflow_txpackets;
	uint64_t                            soflow_txbytes;

	// Feature support (i.e. CFIL, extensible to others)
	uint64_t                            soflow_feat_ctxt_id;
	void                                *soflow_feat_ctxt;

#if defined(NSTAT_EXTENSION_FILTER_DOMAIN_INFO)
	uuid_t                              soflow_uuid;
	nstat_context                       soflow_nstat_context;
#endif
};

/*
 * struct soflow_db
 *
 * For each UDP socket, this is a hash table maintaining all flows
 * keyed by the flow 4-tuples <lport,fport,laddr,faddr>.
 */
struct soflow_db {
	os_refcnt_t                         soflow_db_ref_count;
	struct socket                       *soflow_db_so;
	uint32_t                            soflow_db_count;
	struct soflow_hash_head             *soflow_db_hashbase;
	u_long                              soflow_db_hashmask;
	struct soflow_hash_entry            *soflow_db_only_entry;

	uint8_t                             soflow_db_debug:1;
	uint8_t                             soflow_db_reserved:7;
};

bool soflow_fill_hash_entry_from_address(struct soflow_hash_entry *, bool, struct sockaddr *, bool);
bool soflow_fill_hash_entry_from_inp(struct soflow_hash_entry *, bool, struct inpcb *, bool);
void *soflow_db_get_feature_context(struct soflow_db *, u_int64_t);
u_int64_t soflow_db_get_feature_context_id(struct soflow_db *, struct sockaddr *, struct sockaddr *);

// Per each flow, allow feature to indicate if garbage collection is needed
typedef bool (*soflow_feat_gc_needed_func)(struct socket *so, struct soflow_hash_entry *hash_entry, u_int64_t current_time);

// Per each flow, allow feature to perform garbage collection
typedef bool (*soflow_feat_gc_perform_func)(struct socket *so, struct soflow_hash_entry *hash_entry);

// Per each flow, allow feature to detach and clean up context
typedef bool (*soflow_feat_detach_entry_func)(struct socket *so, struct soflow_hash_entry *hash_entry);

// Per DB, allow feature to detach and clean up context
typedef bool (*soflow_feat_detach_db_func)(struct socket *so, struct soflow_db *db);

void soflow_feat_set_functions(soflow_feat_gc_needed_func, soflow_feat_gc_perform_func,
    soflow_feat_detach_entry_func, soflow_feat_detach_db_func);

typedef bool (*soflow_entry_apply_func)(struct socket *so,
    struct soflow_hash_entry *hash_entry,
    void *context);

bool soflow_db_apply(struct soflow_db *, soflow_entry_apply_func, void *context);

#endif /* BSD_KERNEL_PRIVATE */

__END_DECLS

#endif /* __SOCKET_FLOWS_H__ */
