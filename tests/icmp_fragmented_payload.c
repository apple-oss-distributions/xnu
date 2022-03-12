/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#define _IP_VHL 1

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <darwintest.h>
#include <string.h>
#include <unistd.h>

/*
 * This test helps to reproduce a buffer overflow in the control plane:
 * rdar://84355745
 *
 * The test allows to create a custom ICMP reply, and to send only a portion of it.
 *
 * To reproduce rdar://84355745, the test creates an ICMP "host unreachable" packet
 * that contains a TCP header, and sends the first 28 bytes of the ICMP payload
 * (48 including the outer IP header).
 *
 *  +-----+-----+-----+-----+
 *  | IP  | ICMP| IP  | TCP |
 *  +-----+-----+-----+-----+
 *
 *  <---------------->
 *     sent payload
 *
 * This allows us to ensure that the parsing of the (potentially truncated) TCP
 * headers is done in a secure way.
 */
static void
init_sin_address(struct sockaddr_in *sin)
{
	memset(sin, 0, sizeof(struct sockaddr_in));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
}

static uint16_t
checksum_buffer(uint16_t *buf, size_t len)
{
	unsigned long sum = 0;
	while (len > 1) {
		sum += *buf++;
		len -= 2;
		if (sum & 0x80000000) {
			sum = (sum >> 16) + (sum & 0xFFF);
		}
	}
	if (len == 1) {
		sum += ((unsigned long)(*(uint8_t*)buf) << 8);
	}
	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xFFFF);
	}

	return (uint16_t)~sum;
}

#define MAXICMPBUFLEN 128
typedef struct icmp4_pcb {
	int             fd;
	int             id;
	int             seq;
	int             err;
	int             syserr;
	size_t          txlen;
	uint16_t        icmp_hdr_len;
	struct icmp    *icmp_hdr;
	uint16_t        inner_ip_hdr_len;
	struct ip      *inner_ip_hdr;
	uint16_t        inner_tcp_hdr_len;
	struct tcphdr  *inner_tcp_hdr;
	struct in_addr  in4addr_local;
	struct in_addr  in4addr_remote;
	uint64_t        buf[MAXICMPBUFLEN / 8];
} icmp4_pcb, *icmp4_pcb_t;

static void
icmp4_pcb_print(icmp4_pcb_t pcb)
{
	if (pcb == NULL) {
		fprintf(stdout, "icmp pcb: null");
		return;
	}

	fprintf(stdout, "icmp pcb: \n"
	    "  fd=%d\n"
	    "  id=%d\n"
	    "  seq=%d\n"
	    "  err=%d\n"
	    "  syserr=%d\n"
	    "  txlen=%lu\n"
	    "  ICMP:\n"
	    "    len=%hu\n"
	    "    type=%d\n"
	    "    code=%d\n"
	    "    cksum=%hu\n"
	    "    icmp_id=%hu\n"
	    "    icmp_seq=%hu\n"
	    "    IP:\n"
	    "      len=%hu\n"
	    "      hl=%hu\n"
	    "      cksum=%hu\n"
	    "      TCP:\n"
	    "        len=%hu\n"
	    "        sport=%hu [%hu]\n"
	    "        dport=%hu [%hu]\n"
	    "        cksum=%hu\n",
	    pcb->id,
	    pcb->id,
	    pcb->seq,
	    pcb->err,
	    pcb->syserr,
	    pcb->txlen,
	    pcb->icmp_hdr_len,
	    (uint16_t)(pcb->icmp_hdr == NULL ? -1 : pcb->icmp_hdr->icmp_type),
	    (uint16_t)(pcb->icmp_hdr == NULL ? -1 : pcb->icmp_hdr->icmp_code),
	    (uint16_t)(pcb->icmp_hdr == NULL ? -1 : pcb->icmp_hdr->icmp_cksum),
	    (uint16_t)(pcb->icmp_hdr == NULL ? -1 : pcb->icmp_hdr->icmp_id),
	    (uint16_t)(pcb->icmp_hdr == NULL ? -1 : pcb->icmp_hdr->icmp_seq),
	    pcb->inner_ip_hdr_len,
	    (uint16_t)(pcb->inner_ip_hdr == NULL ? -1 : IP_VHL_HL(pcb->inner_ip_hdr->ip_vhl) << 2),
	    (uint16_t)(pcb->inner_ip_hdr == NULL ? -1 : pcb->inner_ip_hdr->ip_sum),
	    pcb->inner_tcp_hdr_len,
	    (uint16_t)(pcb->inner_tcp_hdr == NULL ? -1 : pcb->inner_tcp_hdr->th_sport),
	    (uint16_t)(pcb->inner_tcp_hdr == NULL ? -1 : ntohs(pcb->inner_tcp_hdr->th_sport)),
	    (uint16_t)(pcb->inner_tcp_hdr == NULL ? -1 : pcb->inner_tcp_hdr->th_dport),
	    (uint16_t)(pcb->inner_tcp_hdr == NULL ? -1 : ntohs(pcb->inner_tcp_hdr->th_dport)),
	    (uint16_t)(pcb->inner_tcp_hdr == NULL ? -1 : pcb->inner_tcp_hdr->th_sum));
}

static void
icmp4_pcb_init(icmp4_pcb_t pcb)
{
	memset(pcb, 0, sizeof(struct icmp4_pcb));
}

static void
icmp4_pcb_close(icmp4_pcb_t pcb)
{
	if (pcb->fd != -1) {
		close(pcb->fd);
		pcb->fd = -1;
	}
}

static int
icmp4_pcb_open(icmp4_pcb_t pcb, struct in_addr *local, struct in_addr *remote)
{
	pcb->fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (pcb->fd == -1) {
		pcb->syserr = errno;
		pcb->err = -1;
		goto out;
	}
	int on = 1;
	if (setsockopt(pcb->fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == -1) {
		pcb->syserr = errno;
		close(pcb->fd);
		pcb->err = -2;
		goto out;
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	memcpy(&sin.sin_addr, local, sizeof(struct in_addr));

	if (bind(pcb->fd, (struct sockaddr*)&sin, sin.sin_len) == -1) {
		pcb->syserr = errno;
		pcb->err = -3;
		goto out;
	}
	memcpy(&(pcb->in4addr_local), local, sizeof(struct in_addr));

	memcpy(&sin.sin_addr, remote, sizeof(struct in_addr));
	if (connect(pcb->fd, (struct sockaddr*)&sin, sin.sin_len) == -1) {
		pcb->syserr = errno;
		pcb->err = -4;
		goto out;
	}
	memcpy(&(pcb->in4addr_remote), remote, sizeof(struct in_addr));

out:
	if (pcb->err != 0) {
		icmp4_pcb_close(pcb);
	}
	return pcb->err;
}

static size_t
icmp4_pcb_get_payload_len(icmp4_pcb_t pcb)
{
	return pcb->icmp_hdr_len + pcb->inner_ip_hdr_len + pcb->inner_ip_hdr_len;
}

static size_t
icmp4_pcb_set_payload(icmp4_pcb_t pcb, struct icmp *icmp_in, struct ip *ip_in, struct tcphdr *tcp_in)
{
	uint8_t *ptr = (uint8_t*)pcb->buf;
	pcb->icmp_hdr_len      = ICMP_MINLEN;
	pcb->inner_ip_hdr_len  = (uint16_t)(IP_VHL_HL(ip_in->ip_vhl) << 2);
	pcb->inner_tcp_hdr_len = sizeof(struct tcphdr);

	pcb->inner_tcp_hdr           = (struct tcphdr*)(ptr + pcb->icmp_hdr_len + pcb->inner_ip_hdr_len);
	pcb->inner_tcp_hdr->th_sport = htons(tcp_in->th_sport);
	pcb->inner_tcp_hdr->th_dport = htons(tcp_in->th_dport);
	pcb->inner_tcp_hdr->th_seq   = htonl(tcp_in->th_seq);
	pcb->inner_tcp_hdr->th_ack   = htonl(tcp_in->th_ack);
	pcb->inner_tcp_hdr->th_flags = tcp_in->th_flags;
	pcb->inner_tcp_hdr->th_sum   = 0;
	pcb->inner_tcp_hdr->th_sum   = checksum_buffer((uint16_t*)pcb->inner_tcp_hdr, pcb->inner_tcp_hdr_len);

	pcb->inner_ip_hdr            = (struct ip*)(ptr + pcb->icmp_hdr_len);
	pcb->inner_ip_hdr->ip_vhl    = ip_in->ip_vhl;
	pcb->inner_ip_hdr->ip_tos    = ip_in->ip_tos;
	pcb->inner_ip_hdr->ip_len    = pcb->inner_tcp_hdr_len + pcb->inner_ip_hdr_len;
	pcb->inner_ip_hdr->ip_id     = 1;
	pcb->inner_ip_hdr->ip_off    = 0;
	pcb->inner_ip_hdr->ip_ttl    = 64;
	pcb->inner_ip_hdr->ip_p      = IPPROTO_TCP;
	pcb->inner_ip_hdr->ip_sum    = 0;
	memcpy(&(pcb->inner_ip_hdr->ip_src), &(pcb->in4addr_local), sizeof(struct in_addr));
	memcpy(&(pcb->inner_ip_hdr->ip_dst), &(pcb->in4addr_remote), sizeof(struct in_addr));
	pcb->inner_ip_hdr->ip_sum    = checksum_buffer((uint16_t*)pcb->inner_ip_hdr, pcb->inner_ip_hdr_len);

	pcb->icmp_hdr = (struct icmp*)pcb->buf;

	pcb->icmp_hdr->icmp_type = icmp_in->icmp_type;
	pcb->icmp_hdr->icmp_code = icmp_in->icmp_code;
	pcb->icmp_hdr->icmp_cksum = 0;
	pcb->icmp_hdr->icmp_id = htons(pcb->id++);
	pcb->icmp_hdr->icmp_seq = htons(pcb->seq++);
	pcb->icmp_hdr->icmp_cksum = checksum_buffer((uint16_t*)pcb->icmp_hdr, sizeof(struct icmp));

	return icmp4_pcb_get_payload_len(pcb);
}

static int
icmp4_pcb_send_unreach(icmp4_pcb_t pcb, size_t maxlen)
{
	size_t out_len = icmp4_pcb_get_payload_len(pcb);
	if (maxlen < out_len) {
		out_len = maxlen;
	}

	fprintf(stderr, "Going to send %lu bytes of ICMP packet\n", out_len);
	ssize_t len = send(pcb->fd, pcb->buf, out_len, 0);

	if (len < 0 || (size_t)len != out_len) {
		pcb->err = -6;
		pcb->syserr = errno;
	} else {
		pcb->err = 0;
	}
	return pcb->err;
}

static void
icmp4_pcb_assert_payload_correct(icmp4_pcb_t pcb, size_t maxlen)
{
	if (pcb == NULL) {
		return;
	}

	T_ASSERT_NE(pcb->inner_ip_hdr, NULL, "IP hdr not set");

	int icmplen = icmp4_pcb_get_payload_len(pcb);
	T_ASSERT_LE(ICMP_MINLEN, icmplen, "ICMP payload smaller than minimal ICMP len");

	T_ASSERT_GE(icmplen, ICMP_ADVLENMIN, "ICMP payload smaller than minimal advertised ICMP len");

	// validate icmplen < ICMP_ADVLEN(icp) (ip_icmp.c:567)
	int inner_ip_hdr_len = (IP_VHL_HL(pcb->inner_ip_hdr->ip_vhl) << 2);
	int icmp_advlen = 8 + inner_ip_hdr_len + 8;
	T_ASSERT_GE(icmplen, icmp_advlen, "ICMP payload smaller than advertised ICMP len");

	// validate inner IP header length (ip_icmp.c:568)
	T_ASSERT_GE(inner_ip_hdr_len, sizeof(struct ip), "IP payload smaller than IP header length");

	// validate that the TCP header is outside of maxlen
	size_t tcp_hdr_offset = (size_t)((uint8_t*)(pcb->inner_tcp_hdr) - (uint8_t*)(pcb->icmp_hdr));
	fprintf(stdout, "tcp_hdr_offset: %lu, maxlen: %lu\n", tcp_hdr_offset, maxlen);
	T_ASSERT_LE(maxlen, tcp_hdr_offset, "TCP header within maxlen");
}

T_DECL(icmp_send_malformed_packet_1, "ICMP packet with malformed TCP header")
{
	struct sockaddr_in sin = {};

	init_sin_address(&sin);
	T_ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr), 1, NULL);

	icmp4_pcb pcb;
	icmp4_pcb_init(&pcb);

	T_ASSERT_EQ(icmp4_pcb_open(&pcb, &sin.sin_addr, &sin.sin_addr), 0, NULL);

	struct icmp icmp_payload = {
		.icmp_type = ICMP_UNREACH,
		.icmp_code = ICMP_UNREACH_HOST,
	};
	struct ip ip_payload = {
		.ip_vhl = 0x45,
		.ip_tos = 0,
		.ip_len = sizeof(struct ip) + sizeof(struct tcphdr),
		.ip_id  = 1,
		.ip_off = 0,
		.ip_ttl = 64,
	};
	struct tcphdr tcp_payload = {
		.th_sport = 1234,
		.th_dport = 80,
		.th_seq = 1024,
		.th_ack = 4096,
		.th_flags = TH_FLAGS,
	};

	T_ASSERT_GT(icmp4_pcb_set_payload(&pcb, &icmp_payload, &ip_payload, &tcp_payload), 0L, NULL);

	icmp4_pcb_print(&pcb);

	size_t sendlen = 28;
	icmp4_pcb_assert_payload_correct(&pcb, sendlen);

	T_ASSERT_EQ(icmp4_pcb_send_unreach(&pcb, sendlen), 0, NULL);

	icmp4_pcb_close(&pcb);
}
