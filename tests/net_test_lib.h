/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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


#ifndef __net_test_lib_h__
#define __net_test_lib_h__

#include <darwintest.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/event.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/bootp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <net/bpf.h>
#include <net/if_bridgevar.h>
#include <net/if_fake_var.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <TargetConditionals.h>
#include <darwintest_utils.h>
#include "inet_transfer.h"
#include "bpflib.h"
#include "in_cksum.h"

extern bool S_debug;

#define DHCP_PAYLOAD_MIN        sizeof(struct bootp)
#define DHCP_FLAGS_BROADCAST    ((u_short)0x8000)

#define FETH_NAME       "feth"

typedef union {
	char            bytes[DHCP_PAYLOAD_MIN];
	/* force 4-byte alignment */
	uint32_t        words[DHCP_PAYLOAD_MIN / sizeof(uint32_t)];
} dhcp_min_payload, *dhcp_min_payload_t;

#define ETHER_PKT_LEN           (ETHER_HDR_LEN + ETHERMTU)
typedef union {
	char            bytes[ETHER_PKT_LEN];
	/* force 4-byte aligment */
	uint32_t        words[ETHER_PKT_LEN / sizeof(uint32_t)];
} ether_packet, *ether_packet_t;

typedef struct {
	struct ip       ip;
	struct udphdr   udp;
} ip_udp_header_t;

typedef struct {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} udp_pseudo_hdr_t;

typedef struct {
	struct ip       ip;
	struct tcphdr   tcp;
} ip_tcp_header_t;

typedef union {
	ip_udp_header_t udp;
	ip_tcp_header_t tcp;
} ip_udp_tcp_header_u;

typedef struct {
	struct in_addr  src_ip;
	struct in_addr  dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} tcp_pseudo_hdr_t;

typedef struct {
	struct ip6_hdr  ip6;
	struct udphdr   udp;
} ip6_udp_header_t;

typedef struct {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	char            zero;
	char            proto;
	unsigned short  length;
} udp6_pseudo_hdr_t;

extern int inet_dgram_socket(void);

extern int inet6_dgram_socket(void);

extern int routing_socket(void);

extern int ifnet_create(int s, const char * ifname);

extern int ifnet_create_2(int s, char * ifname, size_t len);

extern int ifnet_destroy(int s, const char * ifname, bool fail_on_error);

extern void ifnet_get_lladdr(int s, const char * ifname, ether_addr_t * eaddr);

extern int ifnet_attach_ip(int s, char * name);

extern int ifnet_set_flags(int s, const char * ifname,
    uint16_t flags_set, uint16_t flags_clear);

extern int siocdrvspec(int s, const char * ifname,
    u_long op, void *arg, size_t argsize, bool set);

extern int fake_set_peer(int s, const char * feth, const char * feth_peer);

extern u_int ethernet_udp4_frame_populate(void * buf, size_t buf_len,
    const ether_addr_t * src,
    struct in_addr src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    struct in_addr dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len);

extern u_int
ethernet_udp6_frame_populate(void * buf, size_t buf_len,
    const ether_addr_t * src,
    struct in6_addr *src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    struct in6_addr * dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len);


extern u_int make_dhcp_payload(dhcp_min_payload_t payload, ether_addr_t *eaddr);



#endif /* __net_test_lib_h__ */
