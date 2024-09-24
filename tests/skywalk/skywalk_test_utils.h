/*
 * Copyright (c) 2016-2024 Apple Inc. All rights reserved.
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
#ifndef _SKYWALK_TEST_UTILS_H_
#define _SKYWALK_TEST_UTILS_H_

#include <skywalk/os_skywalk_private.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>


typedef enum sktu_if_type {
	SKTU_IFT_UTUN = 1,
	SKTU_IFT_IPSEC = 2,
	SKTU_IFT_FETH = 3,
} sktu_if_type_t;

#define SKTU_IFF_ENABLE_NETIF   0x00000001 // no-netif (txstart bsd interface) by default
#define SKTU_IFF_NO_ATTACH_FSW  0x00000002 // auto-attach fsw for netif by default
typedef uint32_t sktu_if_flag_t;

typedef struct sktc_nexus_handles {
	nexus_controller_t controller;
	uuid_t fsw_prov_uuid;
	uuid_t fsw_nx_uuid;
	uuid_t fsw_nx_host_attach_uuid;
	uuid_t fsw_nx_dev_attach_uuid;
	uuid_t netif_prov_uuid;
	uuid_t netif_nx_uuid;
	uuid_t netif_nx_attach_uuid;
	char netif_ifname[IFNAMSIZ];
	struct in_addr netif_addr;
	struct in_addr netif_mask;
	struct in6_addr netif_ip6_addr;
	uint8_t netif_ip6_prefix_len;
} * sktu_nexus_t;

typedef struct ip_udp_hdr {
	struct ip       ip;
	struct udphdr   udp;
} ip_udp_header_t;

typedef struct ip6_udp_hdr {
	struct ip6_hdr  ip6;
	struct udphdr   udp;
} ip6_udp_header_t;

typedef struct udp_pseudo_hdr {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} udp_pseudo_hdr_t;

struct ipv4_udp_pseudo_hdr {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	uint8_t         zero;
	uint8_t         proto;
	unsigned short  length;
};

struct ipv6_udp_pseudo_hdr {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	uint32_t        length;
	uint8_t         zero[3];
	uint8_t         proto;
};

typedef struct tcp_pseudo_hdr {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	uint8_t         zero;
	uint8_t         proto;
	unsigned short  length;
} tcp_pseudo_hdr_t;

struct ipv4_tcp_pseudo_hdr {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	uint8_t         zero;
	uint8_t         proto;
	uint16_t        length;
};

struct ipv6_tcp_pseudo_hdr {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	uint32_t        length;
	uint8_t         zero[3];
	uint8_t         proto;
};

typedef struct {
	struct ip       ip;
	struct tcphdr   tcp;
} ip_tcp_header_t;

typedef union {
	ip_udp_header_t udp;
	ip_tcp_header_t tcp;
} ip_udp_tcp_header_u;

#define SKTU_MAX_MTU_PAYLOAD_LEN (1500 - (sizeof(struct ip6_hdr) + sizeof(struct tcphdr) - sizeof(uint32_t)))
typedef struct {
	uint32_t        packet_number;
	char            data[SKTU_MAX_MTU_PAYLOAD_LEN];
} my_payload, *my_payload_t;

// sktu_frame is a universal container that holds packet buffer and metadata.
// It's used when packet_t isn't available (like for utun fd), or isn't
// available yet (like before packet gets allocated from channel).
#define SKTU_FRAME_BUF_SIZE (16 * 1024)
typedef struct sktu_frame {
	// meta data
	uuid_t                  flow_uuid;

	bool                    csum_offload;
	uint16_t                csum_flags;
	uint16_t                csum_start;
	uint16_t                csum_stuff;

	size_t                  len;

	// data
	char                    bytes[SKTU_FRAME_BUF_SIZE];
} *sktu_frame_t;

typedef struct {
	channel_t               chan;
	int                     fd;
	nexus_port_t            port;
	channel_ring_t          rx_ring;
	channel_ring_t          tx_ring;
	struct in_addr          ip_addr;
	struct in6_addr         ip6_addr;
	struct ether_addr       mac_addr;
	boolean_t               user_packet_pool;
} channel_port, *channel_port_t, *sktu_channel_port_t;

struct sktu_flow;

#define CSUM_OFFLOAD true
#define NO_CSUM_OFFLOAD false

struct sktu_flow_ops {
	size_t (*create_input_frames)(struct sktu_flow *flow,
	    struct sktu_frame **frames, size_t max_frames, const void *data,
	    size_t data_len);

	size_t (*create_output_frames)(struct sktu_flow *flow,
	    struct sktu_frame **frames, size_t max_frames, const void *data,
	    size_t data_len, bool csum_offload);
};

typedef struct sktu_flow {
	bool                    is_nexus_flow;

	uint8_t                 ipver;
	void                    *src_ip;
	void                    *dst_ip;
	size_t                  ip_addr_len;
	uint16_t                sport;
	uint16_t                dport;
	uint8_t                 ip_protocol;

	size_t                  mtu;

	// nexus flow fields
	struct nx_flow_req      nfr;
	sktu_nexus_t            nexus;
	nexus_port_t            nx_port;
	uuid_t                  uuid;

	// socket flow fields
	int                     sock_fd;

	// ops
	struct sktu_flow_ops    _flow_ops;
#define create_input_frames     _flow_ops.create_input_frames
#define create_output_frames    _flow_ops.create_output_frames
} *sktu_nexus_flow_t;

channel_t
sktu_channel_create_extended(const uuid_t uuid,
    const nexus_port_t port, const ring_dir_t dir,
    const ring_id_t rid, const channel_attr_t attr,
    uint64_t exclusive, uint64_t monitor,
    uint64_t txlowatunit, uint64_t txlowatval,
    uint64_t rxlowatunit, uint64_t rxlowatval,
    uint64_t userpacketpool, uint64_t defunctok,
    uint64_t event_ring, uint64_t low_latency);
void permutefuncP(int n, int *permute, void (*func)(int, int *permute));
void permutefuncH(int n, int *permute, void (*func)(int, int *permute));
void permutefuncR(int n, int *permute, void (*func)(int, int *permute), int total, unsigned seed);
void permutefuncZ(int n, int *permute, void (*func)(int, int *permute));

void sktc_create_flowswitch(struct sktc_nexus_handles *handles, int i);
void sktc_create_flowswitch_no_address(struct sktc_nexus_handles *handles,
    uint64_t tx_slots, uint64_t rx_slots, uint64_t buf_size, uint64_t max_frags,
    uint64_t anonymous);
void sktc_nexus_handles_assign_address(struct sktc_nexus_handles *handles);

void sktc_cleanup_flowswitch(struct sktc_nexus_handles *handles);
int sktc_bind_tcp4_flow(nexus_controller_t ncd, const uuid_t fsw, in_port_t in_port, nexus_port_t nx_port, const uuid_t flow);
int sktc_unbind_flow(nexus_controller_t ncd, const uuid_t fsw, const uuid_t flow);

char * skt_nfr_print(struct nx_flow_req *nfr, char *buf, size_t buf_max);

struct sktu_flow * _sktu_create_nexus_flow(sktu_nexus_t nexus,
    nexus_port_t nx_port, uint8_t af, void *src, void *dst, uint8_t proto,
    uint16_t sport, uint16_t dport, uint32_t flags);
struct sktu_flow * sktu_create_nexus_flow(sktu_nexus_t nexus, uint8_t af,
    void *src, void *dst, uint8_t proto, uint16_t sport, uint16_t dport);
struct sktu_flow * sktu_create_nexus_low_latency_flow(sktu_nexus_t nexus,
    uint8_t af, void *src, void *dst, uint8_t proto, uint16_t sport,
    uint16_t dport);
struct sktu_flow * sktu_create_nexus_flow_with_nx_port(sktu_nexus_t nexus,
    nexus_port_t nx_port, uint8_t af, void *src, void *dst, uint8_t proto,
    uint16_t sport, uint16_t dport);
void _sktu_destroy_nexus_flow(struct sktu_flow *flow);
#define sktu_destroy_nexus_flow(f) \
do { \
	_sktu_destroy_nexus_flow(f); \
	f = NULL; \
} while (0)
int sktu_get_nexus_flow_stats(uuid_t flow_uuid, struct sk_stats_flow *sf);
int sktu_get_nexus_flowswitch_stats(struct sk_stats_flow_switch **sfsw, size_t *len);
void __fsw_stats_print(struct fsw_stats *s);

uint32_t sktc_chew_random(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint32_t avail);
void sktc_pump_ring_nslots_kq(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint64_t nslots, bool verbose);
void sktc_pump_ring_nslots_select(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint64_t nslots, bool verbose);
void sktc_pump_ring_nslots_poll(channel_t channel, channel_ring_t ring, sync_mode_t mode, bool dosync, uint64_t nslots, bool verbose);

void sktc_raise_file_limit(int new);

int sktu_create_interface(sktu_if_type_t type, sktu_if_flag_t flags);
channel_t sktu_create_interface_channel(sktu_if_type_t type, int tunsock);
void sktu_get_interface_name(sktu_if_type_t type, int s, char name[IFNAMSIZ]);

void sktu_dump_buffer(FILE *f, const char *title, const void *p, size_t len);
int sysctl_buf(char *oid_name, void **buffer, size_t *len, void *newp, size_t newlen);
uint32_t sktu_set_inject_error_rmask(uint32_t *);
boolean_t sktu_check_interface_ipv4_address(char *ifname, uint32_t ipaddr);
int sktu_create_pfkeysock(void);
void sktu_create_sa(int keysock, const char ifname[IFXNAMSIZ], uint32_t spi,
    struct in_addr *src, struct in_addr *dst);

extern unsigned short in_cksum(void * pkt, int len, int sum0);
extern uint16_t in_pseudo(uint32_t a, uint32_t b, uint32_t c);
extern uint16_t in6_pseudo(const struct in6_addr *src, const struct in6_addr *dst, uint32_t x);

extern void sktu_channel_port_init(channel_port_t ch_port, uuid_t instance,
    nexus_port_t nx_port, bool enable_upp, bool enable_event_ring, bool low_latency);

extern void skt_channel_port_send(channel_port_t port, uuid_t flow_id,
    int protocol, uint16_t src_port, struct in_addr dst_ip, uint16_t dst_port,
    my_payload_t payload, int payload_length, uint32_t limit,
    boolean_t must_complete_batch, boolean_t connect,
    packet_svc_class_t svc_class, boolean_t csum_offload,
    void (^packet_prehook)(packet_t p));

extern void skt_channel_port_receive(int child, channel_port_t port,
    uint16_t our_port, struct in_addr peer_ip, uint32_t limit,
    uint32_t *receive_count, uint32_t *receive_index, boolean_t errors_ok,
    uint32_t * pkts_dropped);

extern void sktu_channel_port_tx_bulk(channel_port_t port,
    struct sktu_frame **frames, uint32_t n);

extern packet_t sktu_channel_port_frame_to_pkt(channel_port_t port,
    struct sktu_frame *frame);
extern uint32_t sktu_channel_port_tx_burst_pkt(channel_port_t port,
    packet_t *frames, uint32_t n);
extern uint32_t sktu_channel_port_rx_burst(channel_port_t port,
    struct sktu_frame **frames, uint32_t n);
extern uint32_t sktu_channel_port_tx_burst(channel_port_t port,
    struct sktu_frame **frames, uint32_t n);

extern uint32_t sktu_utun_fd_rx_burst(int utun_fd, struct sktu_frame **frames,
    uint32_t n);

extern void sktu_utun_fd_tx_burst(int utun_fd, struct sktu_frame **frames,
    uint32_t n);

extern struct sktu_frame * sktu_frame_alloc();
#define sktu_frame_free(frame) \
do { \
	free(frame); \
	frame = NULL; \
} while (0)

extern void sktu_frames_free(struct sktu_frame **frames, size_t n);

extern size_t sktu_create_ip_frames(struct sktu_frame **frames, size_t n,
    void *src_ip, void *dst_ip, uint8_t proto, const void *sdu, size_t sdu_len,
    size_t mtu, uint16_t csum_flags, uint16_t csum_start, uint16_t csum_stuff);
extern size_t sktu_create_ip6_frames(struct sktu_frame **frames, size_t n,
    void *src_ip, void *dst_ip, uint8_t proto, const void *sdu, size_t sdu_len,
    size_t mtu, uint16_t csum_flags, uint16_t csum_start, uint16_t csum_stuff);
extern size_t sktu_create_tcp_frames(struct sktu_frame **frames, size_t n,
    uint8_t ipver, void *src_ip, void *dst_ip, uint16_t sport, uint16_t dport,
    const void *data, size_t data_len, size_t mtu, bool csum_offload);
extern size_t sktu_create_udp_frames(struct sktu_frame **frames, size_t n,
    uint8_t ipver, void *src_ip, void *dst_ip, uint16_t sport, uint16_t dport,
    const void *data, size_t data_len, size_t mtu, bool csum_offload);

extern int sktu_parse_ipv4_frame(struct sktu_frame *frame, void *ip_payload,
    uint32_t *ip_payload_len);
extern int sktu_parse_tcp4_frame(struct sktu_frame *frame, void *tcp_payload,
    uint32_t *tcp_payload_len);
extern int sktu_parse_udp4_frame(struct sktu_frame *frame, void *udp_payload,
    uint32_t *udp_payload_len);

#endif /* _SKYWALK_TEST_UTILS_H_ */
