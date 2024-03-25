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

#ifndef _NET_IF_PORT_USED_H_
#define _NET_IF_PORT_USED_H_

#ifdef PRIVATE

#include <sys/types.h>
#include <stdint.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/_types/_timeval32.h>
#include <net/if.h>
#include <netinet/in.h>
#include <uuid/uuid.h>
#include <stdbool.h>

#define IP_PORTRANGE_SIZE 65536

/*
 * The sysctl "net.link.generic.system.port_used.list" returns:
 *  - one "struct xnpigen" as a preamble
 *  - zero or more "struct net_port_info" according to xng_npi_count
 *
 * The list may contain information several interfaces if several drivers
 * queried the list of port to offload
 *
 * The same local port may have more than one "struct net_port_info" on
 * a given interface, for example when a local server has mutiple clients
 * connections
 */

struct xnpigen {
	uint32_t        xng_len; /* length of this data structure */
	uint32_t        xng_gen; /* how many times the list was built */
	uint32_t        xng_npi_count; /* number of net_port_info following */
	uint32_t        xng_npi_size; /* number of struct net_port_info  */
	uuid_t          xng_wakeuuid; /* WakeUUID when list was built */
};

union in_addr_4_6 {
	struct in_addr  _in_a_4;
	struct in6_addr _in_a_6;
};

#define NPIF_IPV4       0x0001
#define NPIF_IPV6       0x0002
#define NPIF_TCP        0x0004
#define NPIF_UDP        0x0008
#define NPIF_DELEGATED  0x0010
#define NPIF_SOCKET     0x0020
#define NPIF_CHANNEL    0x0040
#define NPIF_LISTEN     0x0080
#define NPIF_WAKEPKT    0x0100
#define NPIF_NOWAKE     0x0200  /* flow marked with SO_NOWAKEFROMSLEEP are normally excluded */
#define NPIF_FRAG       0x0400  /* packet is pure fragment (i.e. no src and dst port) */
#define NPIF_ESP        0x0800  /* for logging only */
#define NPIF_COMPLINK   0x1000  /* interface is companion link */

#define NPI_HAS_EFFECTIVE_UUID 1

struct net_port_info {
	uint16_t                npi_if_index;
	uint16_t                npi_flags; /* NPIF_xxx */
	struct timeval32        npi_timestamp; /* when passed to driver */
	uuid_t                  npi_flow_uuid;
	in_port_t               npi_local_port; /* network byte order */
	in_port_t               npi_foreign_port; /* network byte order */
	union in_addr_4_6       npi_local_addr_;
	union in_addr_4_6       npi_foreign_addr_;
	pid_t                   npi_owner_pid;
	pid_t                   npi_effective_pid;
	char                    npi_owner_pname[MAXCOMLEN + 1];
	char                    npi_effective_pname[MAXCOMLEN + 1];
	uuid_t                  npi_owner_uuid;
	uuid_t                  npi_effective_uuid;
};

#define npi_local_addr_in npi_local_addr_._in_a_4
#define npi_foreign_addr_in npi_foreign_addr_._in_a_4

#define npi_local_addr_in6 npi_local_addr_._in_a_6
#define npi_foreign_addr_in6 npi_foreign_addr_._in_a_6

#define NPI_HAS_WAKE_EVENT_TUPLE 1
#define NPI_HAS_PACKET_INFO 1
#define NPI_HAS_PHYSICAL_LINK 1 /* npi_if_info and phy_if fields are present */

/*
 * struct npi_if_info provides detailed information about the kind of interface
 *
 * See <net/if_private.h> for definitions of possible values of each field
 *
 * Note: the IFRTYPE_xxx values are the same as the IFNET_xxx used inside the kernel
 */
struct npi_if_info {
	uint32_t            npi_if_family; /* IFRTYPE_FAMILY_xxx */
	uint32_t            npi_if_subfamily; /* IFRTYPE_SUBFAMILY_xxx */
	uint32_t            npi_if_functional_type; /* IFRTYPE_FUNCTIONAL_xxx */
};

#define NPI_IF_INFO_IS_ETHERNET(_npi) \
    ((_npi)->npi_if_family == IFRTYPE_FAMILY_ETHERNET)

#define NPI_IF_INFO_IS_ETHERNET_WIRED(_npi) \
    (NPI_IF_INFO_IS_ETHERNET(_npi) && \
    (_npi)->npi_if_subfamily != IFRTYPE_SUBFAMILY_WIFI)

#define NPI_IF_INFO_IS_WIFI(_npi) \
    (NPI_IF_INFO_IS_ETHERNET(_npi) && \
    (_npi)->npi_if_subfamily == IFRTYPE_SUBFAMILY_WIFI)

#define NPI_IF_INFO_IS_CELLULAR(_npi) \
    ((_npi)->npi_if_family == IFRTYPE_FAMILY_CELLULAR)

#define NPI_IF_INFO_IS_IPSEC(_npi) \
    ((_npi)->npi_if_family == IFRTYPE_FAMILY_IPSEC)

#define NPI_IF_INFO_IS_IPSEC_COMPANIONLINK(_npi) \
    ((_npi)->npi_if_family == IFRTYPE_FAMILY_IPSEC && \
    (_npi)->npi_if_functional_type == IFRTYPE_FUNCTIONAL_COMPANIONLINK)

#define NPI_IF_INFO_IS_IPSEC_COMPANIONLINK_BLUETOOTH(_npi) \
    (NPI_IF_INFO_IS_IPSEC_COMPANIONLINK(_npi) && \
    (_npi)->npi_if_subfamily == IFRTYPE_SUBFAMILY_BLUETOOTH)

#define NPI_IF_INFO_IS_IPSEC_COMPANIONLINK_WIFI(_npi) \
    (NPI_IF_INFO_IS_IPSEC_COMPANIONLINK(_npi) && \
    (_npi)->npi_if_subfamily == IFRTYPE_SUBFAMILY_WIFI)

#define NPI_IF_INFO_IS_IPSEC_COMPANIONLINK_QUICKRELAY(_npi) \
    (NPI_IF_INFO_IS_IPSEC_COMPANIONLINK(_npi) && \
    (_npi)->npi_if_subfamily == IFRTYPE_SUBFAMILY_QUICKRELAY)

#define NPI_IF_INFO_IS_UTUN(_npi) \
    ((_npi)->npi_if_family == IFRTYPE_FAMILY_UTUN)

/*
 * Symbolic names for bits of wake_pkt_control_flags and una_wake_pkt_control_flags
 * When the protocol is TCP (flag NPIF_TCP set) the lower 8 bits correspond to the TCP header flag
 */
#define NPICF_TH_FIN  0x01
#define NPICF_TH_SYN  0x02
#define NPICF_TH_RST  0x04
#define NPICF_TH_PUSH 0x08
#define NPICF_TH_ACK  0x10
#define NPICF_TH_URG  0x20
#define NPICF_TH_ECE  0x40
#define NPICF_TH_CWR  0x80
#define NPICF_NOWAKE  0x1000

/*
 * struct net_port_info_una_wake_event is the event data for KEV_POWER_WAKE_PACKE
 *
 * See <net/if_private.h> for definiton of values of these kinds of fields:
 *  - xxx_if_family             IFRTYPE_FAMILY_YYY
 *  - xxx_if_subfamily          IFRTYPE_SUBFAMILY_YYY
 *  - xxx_if_functional_type    IFRTYPE_FUNCTIONAL_YYY
 */
struct net_port_info_wake_event {
	uuid_t              wake_uuid;
	struct timeval32    wake_pkt_timestamp; /* when processed by networking stack */
	uint16_t            wake_pkt_if_index; /* interface of incoming wake packet */
	in_port_t           wake_pkt_port; /* local port in network byte order */
	uint16_t            wake_pkt_flags; /* NPIF_xxx */
	pid_t               wake_pkt_owner_pid;
	pid_t               wake_pkt_effective_pid;
	char                wake_pkt_owner_pname[MAXCOMLEN + 1];
	char                wake_pkt_effective_pname[MAXCOMLEN + 1];
	uuid_t              wake_pkt_owner_uuid;
	uuid_t              wake_pkt_effective_uuid;
	in_port_t           wake_pkt_foreign_port; /* network byte order */
	union in_addr_4_6   wake_pkt_local_addr_;
	union in_addr_4_6   wake_pkt_foreign_addr_;
	char                wake_pkt_ifname[IFNAMSIZ]; /* name + unit */

	/* Following fields added with NPI_HAS_PACKET_INFO */
	uint32_t            wake_pkt_total_len; /* actual length of packet */
	uint32_t            wake_pkt_data_len; /* exclude transport (TCP/UDP) header length */
	uint16_t            wake_pkt_control_flags; /* see NPICF_xxx above */

	/* Followings fields added with NPI_HAS_PHYSICAL_LINK */
	struct npi_if_info  wake_pkt_if_info;  /* inner-most interface of TCP/UDP packet */

	char                wake_pkt_phy_ifname[IFNAMSIZ]; /* name + unit */
	struct npi_if_info  wake_pkt_phy_if_info; /* outer-most interface of wake packet */
};

/*
 * struct net_port_info_una_wake_event is the event data for KEV_POWER_UNATTRIBUTED_WAKE
 *
 * una_wake_pkt_proto is useful to track unexpected wake packets when NPIF_IPV4 or
 * NPIF_IPV6 is set this is the IP protocol -- see IPPROTO_x from netinet/in.h.
 * When NPIF_IPV4 and NPIF_IPV6 are not set the cotent of una_wake_pkt can give clues
 * on the type of unexpected wake packet
 */
#define NPI_MAX_UNA_WAKE_PKT_LEN 102
struct net_port_info_una_wake_event {
	uuid_t              una_wake_uuid;
	struct timeval32    una_wake_pkt_timestamp; /* when processed by networking stack */
	uint16_t            una_wake_pkt_if_index; /* interface of incoming wake packet */
	uint16_t            una_wake_pkt_flags; /* NPIF_xxx */
	uint16_t            _una_wake_pkt_reserved; /* not used */
	uint16_t            una_wake_ptk_len; /* length of una_wake_pkt */
	uint8_t             una_wake_pkt[NPI_MAX_UNA_WAKE_PKT_LEN]; /* initial portion of the IPv4/IPv6 packet  */
	in_port_t           una_wake_pkt_local_port; /* network byte order */
	in_port_t           una_wake_pkt_foreign_port; /* network byte order */
	union in_addr_4_6   una_wake_pkt_local_addr_;
	union in_addr_4_6   una_wake_pkt_foreign_addr_;
	char                una_wake_pkt_ifname[IFNAMSIZ]; /* name + unit */

	/* Following fields added with NPI_HAS_PACKET_INFO */
	uint32_t            una_wake_pkt_total_len; /* actual length of packet */
	uint32_t            una_wake_pkt_data_len; /* exclude transport (TCP/UDP) header length */
	uint16_t            una_wake_pkt_control_flags; /* see NPICF_xxx above */
	uint16_t            una_wake_pkt_proto; /* IPv4 or IPv6 protocol */

	/* Followings fields added with NPI_HAS_PHYSICAL_LINK */
	struct npi_if_info  una_wake_pkt_if_info; /* inner-most interface for TCP/UDP tuple  */

	char                una_wake_pkt_phy_ifname[IFNAMSIZ]; /* name + unit */
	struct npi_if_info  una_wake_pkt_phy_if_info; /* outer-most interface of wake packet */
};

#define IFPU_HAS_MATCH_WAKE_PKT_NO_FLAG 1 /* ifpu_match_wake_pkt_no_flag is defined */

#define IF_PORTS_USED_STATS_LIST \
	X(uint64_t, ifpu_wakeuid_gen, "wakeuuid generation%s", "", "s") \
	X(uint64_t, ifpu_wakeuuid_not_set_count, "offload port list quer%s with wakeuuid not set", "y", "ies") \
	X(uint64_t, ifpu_npe_total, "total offload port entr%s created since boot", "y", "ies") \
	X(uint64_t, ifpu_npe_count, "current offload port entr%s", "y", "ies") \
	X(uint64_t, ifpu_npe_max, "max offload port entr%s", "y", "ies") \
	X(uint64_t, ifpu_npe_dup, "duplicate offload port entr%s", "y", "ies") \
	X(uint64_t, ifpu_npi_hash_search_total, "total table entry search%s", "", "es") \
	X(uint64_t, ifpu_npi_hash_search_max, "max hash table entry search%s", "", "es") \
	X(uint64_t, ifpu_so_match_wake_pkt, "match so wake packet call%s", "", "s") \
	X(uint64_t, ifpu_ch_match_wake_pkt, "match ch wake packet call%s", "", "s") \
	X(uint64_t, ifpu_ipv4_wake_pkt, "IPv4 wake packet%s", "", "s") \
	X(uint64_t, ifpu_ipv6_wake_pkt, "IPv6 wake packet%s", "", "s") \
	X(uint64_t, ifpu_tcp_wake_pkt, "TCP wake packet%s", "", "s") \
	X(uint64_t, ifpu_udp_wake_pkt, "UDP wake packet%s", "", "s") \
	X(uint64_t, ifpu_isakmp_natt_wake_pkt, "ISAKMP NAT traversal wake packet%s", "", "s") \
	X(uint64_t, ifpu_esp_wake_pkt, "ESP wake packet%s", "", "s") \
	X(uint64_t, ifpu_bad_proto_wake_pkt, "bad protocol wake packet%s", "", "s") \
	X(uint64_t, ifpu_bad_family_wake_pkt, "bad family wake packet%s", "", "s") \
	X(uint64_t, ifpu_wake_pkt_event, "wake packet event%s", "", "s") \
	X(uint64_t, ifpu_dup_wake_pkt_event, "duplicate wake packet event%s in same wake cycle", "", "s") \
	X(uint64_t, ifpu_wake_pkt_event_error, "wake packet event%s undelivered", "", "s") \
	X(uint64_t, ifpu_unattributed_wake_event, "unattributed wake packet event%s", "", "s") \
	X(uint64_t, ifpu_dup_unattributed_wake_event, "duplicate unattributed wake packet event%s in same wake cycle", "", "s") \
	X(uint64_t, ifpu_unattributed_wake_event_error, "unattributed wake packet event%s undelivered", "", "s") \
	X(uint64_t, ifpu_unattributed_null_recvif, "unattributed wake packet%s received with null interface", "", "s") \
	X(uint64_t, ifpu_match_wake_pkt_no_flag, "bad packet%s without wake flag", "", "s") \
	X(uint64_t, ifpu_frag_wake_pkt, "pure fragment wake packet%s", "", "s") \
	X(uint64_t, ifpu_incomplete_tcp_hdr_pkt, "packet%s with incomplete TCP header", "", "s") \
	X(uint64_t, ifpu_incomplete_udp_hdr_pkt, "packet%s with incomplete UDP header", "", "s") \
	X(uint64_t, ifpu_npi_not_added_no_wakeuuid, "port entr%s not added with wakeuuid not set", "y", "ies") \
	X(uint64_t, ifpu_deferred_isakmp_natt_wake_pkt, "deferred matching of ISAKMP NAT traversal wake packet%s", "", "s") \
	X(uint64_t, ifpu_spurious_wake_event, "spurious wake packet event%s", "", "s")

struct if_ports_used_stats {
#define X(_type, _field, ...) _type _field;
	IF_PORTS_USED_STATS_LIST
#undef X
};

#ifdef XNU_KERNEL_PRIVATE

extern int if_ports_used_verbose;

void if_ports_used_init(void);

void if_ports_used_update_wakeuuid(struct ifnet *);

struct inpcb;
bool if_ports_used_add_inpcb(const uint32_t ifindex, const struct inpcb *inp);

#if SKYWALK
struct ns_flow_info;
struct flow_entry;
bool if_ports_used_add_flow_entry(const struct flow_entry *fe, const uint32_t ifindex,
    const struct ns_flow_info *nfi, uint32_t ns_flags);
void if_ports_used_match_pkt(struct ifnet *ifp, struct __kern_packet *pkt);
#endif /* SKYWALK */

void if_ports_used_match_mbuf(struct ifnet *ifp, protocol_family_t proto_family,
    struct mbuf *m);

#endif /* XNU_KERNEL_PRIVATE */
#endif /* PRIVATE */

#endif /* _NET_IF_PORT_USED_H_ */
