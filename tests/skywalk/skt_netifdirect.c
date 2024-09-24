/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <mach/mach_time.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

//#define SKT_NETIF_DIRECT_DEBUG 1

#define STR(x) _STR(x)
#define _STR(x) #x

#if TARGET_OS_WATCH
#define NETIF_TXRX_PACKET_COUNT  (5 * 1000)
#define NETIF_TXRX_BATCH_COUNT   4
#define NETIF_TXRX_TIMEOUT_SECS  0
#define NETIF_TXRX_TIMEOUT_NSECS (100 * 1000 * 1000)
#define NETIF_IFADV_INTERVAL     30
#define NETIF_TX_PKT_DROP_RATE   100
#else /* TARGET_OS_WATCH */
#define NETIF_TXRX_PACKET_COUNT  (20 * 1000)
#define NETIF_TXRX_BATCH_COUNT   8
#define NETIF_TXRX_TIMEOUT_SECS  0
#define NETIF_TXRX_TIMEOUT_NSECS (100 * 1000 * 1000)
#define NETIF_IFADV_INTERVAL     30
#define NETIF_TX_PKT_DROP_RATE   100
#endif /* !TARGET_OS_WATCH */

#define FETH0_UDP_PORT    0x1234
#define FETH1_UDP_PORT    0x5678

/* test identifiers for netif direct channel tests */
#define SKT_NETIF_DIRECT_TEST_TXRX               1
#define SKT_NETIF_DIRECT_TEST_IF_ADV_ENABLED     2
#define SKT_NETIF_DIRECT_TEST_IF_ADV_DISABLED    3
#define SKT_NETIF_DIRECT_TEST_CHANNEL_EVENTS     4
#define SKT_NETIF_DIRECT_TEST_EXPIRY_EVENTS      5


/* netif event flags */
#define SKT_NETIF_DIRECT_EVFLAG_IFADV      0x1
#define SKT_NETIF_DIRECT_EVFLAG_CHANNEL    0x2
#define SKT_NETIF_DIRECT_EVFLAG_EXPIRY     0x4

/* dummy packet identifier constants */
#define NETIF_PKTID_PAYLOAD_TYPE    0xFA
#define NETIF_PKTID_STREAM_ID       0xFB

/* Expiry notification parameters */
#define SKT_NETIF_DIRECT_TEST_EXPIRY_DEADLINE_NS   15


#define SKT_ETH_IPV6_UDP_HDR_LEN    \
    (sizeof(struct ether_header) + sizeof(struct ip6_hdr) + \
    sizeof(struct udphdr))

typedef struct {
	uint32_t    packet_number;
	char        data[1514 - SKT_ETH_IPV6_UDP_HDR_LEN - sizeof(uint32_t)];
} netif_payload, *netif_payload_t;

static struct sktc_nexus_handles handles;

static struct mach_timebase_info timebase_info = {0, 0};
#define SKT_NETIF_TIMESTAMP_MACH_TO_NS(ts_mach) \
	((int64_t)(((ts_mach) * timebase_info.denom) / timebase_info.numer))
#define SKT_NETIF_TIMESTAMP_NS_TO_MACH(ts_ns)   \
	((int64_t)(((ts_ns) * timebase_info.numer) / timebase_info.denom))

static uint64_t expiration_deadline_mach = 0;

static void
init_expiration_deadline_mach(void)
{
	uint64_t deadline_ns = SKT_NETIF_DIRECT_TEST_EXPIRY_DEADLINE_NS;
	assert(mach_timebase_info(&timebase_info) == KERN_SUCCESS);
	expiration_deadline_mach = SKT_NETIF_TIMESTAMP_NS_TO_MACH(deadline_ns);
}

static void
skt_add_netif_ipv6_flow(
	struct sktc_nexus_handles *handles,
	const struct in6_addr *our_ip,
	const struct in6_addr *peer_ip,
	uint16_t flags,
	nexus_port_t *nx_port)
{
	int error;
	struct nx_flow_req nfr;
	struct sockaddr_in6 *sin6;

	bzero(&nfr, sizeof(nfr));
	uuid_generate(nfr.nfr_flow_uuid);
	nfr.nfr_nx_port = NEXUS_PORT_ANY;
	nfr.nfr_flags |= flags;

	if (our_ip) {
		sin6 = &nfr.nfr_saddr.sin6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		sin6->sin6_family = AF_INET6;
		bcopy(our_ip, &sin6->sin6_addr, sizeof(*our_ip));
	}

	if (peer_ip) {
		sin6 = &nfr.nfr_daddr.sin6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		sin6->sin6_family = AF_INET6;
		bcopy(peer_ip, &sin6->sin6_addr, sizeof(*peer_ip));
	}

	error = __os_nexus_flow_add(handles->controller,
	    handles->netif_nx_uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);

	if (nx_port) {
		*nx_port = nfr.nfr_nx_port;
	}
}

static void
skt_setup_netif_with_ipv6_flow(struct sktc_nexus_handles *handles,
    const char *ifname, struct in6_addr *our_ip, struct in6_addr *peer_ip,
    nexus_port_t *nx_port)
{
	bzero(handles, sizeof(*handles));
	strlcpy(handles->netif_ifname, ifname, sizeof(handles->netif_ifname));
	handles->controller = os_nexus_controller_create();
	assert(handles->controller != NULL);
	handles->netif_ip6_addr = *our_ip;
	assert(sktc_get_netif_nexus(handles->netif_ifname,
	    handles->netif_nx_uuid));
	/*
	 * Add listener flow just to execute listener code path, the flow
	 * itself is not used for anything atm.
	 */
	skt_add_netif_ipv6_flow(handles, NULL, NULL,
	    NXFLOWREQF_IPV6_ULA | NXFLOWREQF_LISTENER, NULL);
	skt_add_netif_ipv6_flow(handles, our_ip, peer_ip,
	    NXFLOWREQF_IPV6_ULA, nx_port);
}

static size_t
skt_netif_ipv6_udp_frame_populate(packet_t ph, struct ether_addr *src_mac,
    struct in6_addr *src_ip, uint16_t src_port, struct ether_addr *dst_mac,
    struct in6_addr *dst_ip, uint16_t dst_port, const void *data,
    size_t data_len)
{
	int                     error;
	size_t                  frame_length;
	struct ether_header     eth_hdr;
	struct ip6_hdr          ip6_hdr;
	struct udphdr           udp_hdr, *udp_hdr_p;
	char                    *baddr;
	buflet_t                buf;
	uint16_t                bdlim;

	buf = os_packet_get_next_buflet(ph, NULL);
	assert(buf != NULL);
	error = os_buflet_set_data_offset(buf, 0);
	SKTC_ASSERT_ERR(error == 0);
	bdlim = os_buflet_get_data_limit(buf);
	assert(bdlim != 0);
	baddr = os_buflet_get_object_address(buf);
	assert(baddr != NULL);

	frame_length = SKT_ETH_IPV6_UDP_HDR_LEN + data_len;
	assert(os_packet_get_buflet_count(ph) == 1);
	assert(bdlim >= frame_length);

	/* frame ethernet header */
	bcopy(src_mac->octet, eth_hdr.ether_shost, ETHER_ADDR_LEN);
	bcopy(dst_mac->octet, eth_hdr.ether_dhost, ETHER_ADDR_LEN);
	eth_hdr.ether_type = htons(ETHERTYPE_IPV6);
	bcopy(&eth_hdr, baddr, sizeof(eth_hdr));
	baddr += sizeof(eth_hdr);
	error = os_packet_set_link_header_length(ph, sizeof(eth_hdr));
	SKTC_ASSERT_ERR(error == 0);

	/* frame IPv6 header */
	ip6_hdr.ip6_vfc = IPV6_VERSION;
	ip6_hdr.ip6_flow |= (IPV6_FLOWINFO_MASK & 0);
	ip6_hdr.ip6_plen = htons(data_len + sizeof(udp_hdr));
	ip6_hdr.ip6_nxt = IPPROTO_UDP;
	ip6_hdr.ip6_hlim = IPV6_DEFHLIM;
	ip6_hdr.ip6_src = *src_ip;
	ip6_hdr.ip6_dst = *dst_ip;
	bcopy(&ip6_hdr, baddr, sizeof(ip6_hdr));
	baddr += sizeof(ip6_hdr);

	/* frame UDP header */
	udp_hdr_p = (struct udphdr *)baddr;
	udp_hdr.uh_ulen = htons(data_len + sizeof(udp_hdr));
	udp_hdr.uh_sport = htons(src_port);
	udp_hdr.uh_dport = htons(dst_port);
	/* psuedo header checksum */
	udp_hdr.uh_sum = in6_pseudo(src_ip, dst_ip,
	    htonl(ntohs(udp_hdr.uh_ulen) + ip6_hdr.ip6_nxt));
	bcopy(&udp_hdr, baddr, sizeof(udp_hdr));
	baddr += sizeof(udp_hdr);

	/* copy the data */
	bcopy(data, baddr, data_len);
	error = os_buflet_set_data_length(buf, frame_length);
	SKTC_ASSERT_ERR(error == 0);
	udp_hdr_p->uh_sum = in_cksum(udp_hdr_p, ntohs(udp_hdr.uh_ulen), 0);
	return frame_length;
}

static size_t
skt_netif_ipv6_udp_frame_process(packet_t ph, void *data, size_t data_max)
{
	buflet_t buflet;
	size_t pkt_len, buf_len, ip_plen, udp_data_len;
	char *buf;
	struct ether_header *eth_hdr;
	struct ip6_hdr *ip6_hdr;
	struct udphdr *udp_hdr;
	uint16_t csum;

	assert(os_packet_get_buflet_count(ph) == 1);
	buflet = os_packet_get_next_buflet(ph, NULL);
	assert(buflet != NULL);
	buf_len = os_buflet_get_data_length(buflet);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	assert(os_packet_get_link_header_length(ph) == sizeof(*eth_hdr));
	eth_hdr = (struct ether_header *)buf;
	assert(ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6);
	ip6_hdr = (struct ip6_hdr *)(buf + sizeof(*eth_hdr));
	pkt_len = os_packet_get_data_length(ph);
	ip_plen = ntohs(ip6_hdr->ip6_plen);
	assert(pkt_len == (sizeof(*eth_hdr) + sizeof(*ip6_hdr) + ip_plen));
	assert(ip6_hdr->ip6_nxt == IPPROTO_UDP);
	udp_hdr = (struct udphdr *)(buf + sizeof(*eth_hdr) + sizeof(*ip6_hdr));
	udp_data_len = ntohs(udp_hdr->uh_ulen) - sizeof(*udp_hdr);
	assert(udp_data_len == (pkt_len - SKT_ETH_IPV6_UDP_HDR_LEN));
	assert(data_max == 0 || udp_data_len <= data_max);

	/* verify UDP checksum */
	csum = in6_pseudo((void *)&ip6_hdr->ip6_src, (void *)&ip6_hdr->ip6_dst,
	    htonl(ntohs(udp_hdr->uh_ulen) + ip6_hdr->ip6_nxt));
	assert(in_cksum(udp_hdr, ntohs(udp_hdr->uh_ulen), csum) == 0);

	if (data != NULL) {
		bcopy((buf + SKT_ETH_IPV6_UDP_HDR_LEN), data, udp_data_len);
	}
	return udp_data_len;
}

static void
skt_netif_channel_send(channel_port_t port, uint16_t src_port,
    struct ether_addr *dst_mac, struct in6_addr *dst_ip, uint16_t dst_port,
    netif_payload_t payload, int payload_length, uint32_t limit,
    void (^packet_prehook)(packet_t p))
{
	int error;
	channel_slot_t last_slot = NULL;
	packet_id_t pktid = {OS_PACKET_PKTID_VERSION_CURRENT,
		             NETIF_PKTID_PAYLOAD_TYPE, 0, 0, NETIF_PKTID_STREAM_ID, 0};

	assert(payload->packet_number < limit);
	while (1) {
		int                     frame_length;
		slot_prop_t             prop;
		channel_slot_t          slot;
		packet_t                pkt = 0;
		void                    *buf;
		size_t                  buf_len;
		buflet_t                buflet;

		/* grab a slot and populate it */
		slot = os_channel_get_next_slot(port->tx_ring, last_slot,
		    &prop);
		if (slot == NULL) {
			if (payload->packet_number < limit) {
				/* couldn't complete batch */
#if SKT_NETIF_DIRECT_DEBUG
				T_LOG(
					"TX didn't complete batch (%u < %u)\n",
					payload->packet_number, limit);
#endif
			}
			break;
		}
		if (port->user_packet_pool) {
			assert(prop.sp_buf_ptr == 0);
			assert(prop.sp_len == 0);
			error = os_channel_packet_alloc(port->chan, &pkt);
			SKTC_ASSERT_ERR(error == 0);
		} else {
			assert(prop.sp_buf_ptr != 0);
			assert(prop.sp_len != 0);
			pkt = os_channel_slot_get_packet(port->tx_ring, slot);
		}
		assert(pkt != 0);
		buflet = os_packet_get_next_buflet(pkt, NULL);
		assert(buflet != NULL);
		buf = os_buflet_get_object_address(buflet) +
		    os_buflet_get_data_offset(buflet);
		assert(buf != NULL);
		buf_len = os_buflet_get_data_limit(buflet);
		assert(buf_len != 0);
		if (!port->user_packet_pool) {
			assert(buf == (void *)prop.sp_buf_ptr);
			assert(buf_len == prop.sp_len);
		}
		frame_length = skt_netif_ipv6_udp_frame_populate(pkt,
		    &port->mac_addr, &port->ip6_addr, src_port,
		    dst_mac, dst_ip, dst_port, (void *)payload, payload_length);
		pktid.pktid_sequence_number = payload->packet_number;
		pktid.pktid_timestamp = pktid.pktid_sequence_number;
		assert(os_packet_set_packetid(pkt, &pktid) == 0);

		if (packet_prehook != NULL) {
			packet_prehook(pkt);
		}

		error = os_packet_finalize(pkt);
		SKTC_ASSERT_ERR(error == 0);
#if SKT_NETIF_DIRECT_DEBUG
		T_LOG("\nPort %d transmitting %d bytes:\n",
		    port->port, frame_length);
#endif
		assert(frame_length != 0);
		if (port->user_packet_pool) {
			error = os_channel_slot_attach_packet(port->tx_ring,
			    slot, pkt);
			SKTC_ASSERT_ERR(error == 0);
		} else {
			prop.sp_len = frame_length;
			os_channel_set_slot_properties(port->tx_ring, slot,
			    &prop);
		}
		last_slot = slot;
		payload->packet_number++;
		if (payload->packet_number >= limit) {
			break;
		}
	}
	if (last_slot != NULL) {
		error = os_channel_advance_slot(port->tx_ring, last_slot);
		SKTC_ASSERT_ERR(error == 0);
		error = os_channel_sync(port->chan, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
	}
}

static void
skt_netif_channel_receive(int child, channel_port_t port, uint32_t limit,
    uint32_t *receive_count, uint32_t *receive_index, boolean_t errors_ok,
    uint32_t *pkts_dropped)
{
	int error;
	channel_slot_t last_slot = NULL;
	int frame_length = SKT_ETH_IPV6_UDP_HDR_LEN + sizeof(netif_payload);

	assert(*receive_index < limit);
	*pkts_dropped = 0;

	while (1) {
		netif_payload           payload;
		slot_prop_t             prop;
		channel_slot_t          slot;
		packet_t                pkt;
		char                    *buf;
		uint16_t                bdoff, pkt_len;
		buflet_t                buflet;

		slot = os_channel_get_next_slot(port->rx_ring, last_slot,
		    &prop);
		if (slot == NULL) {
			break;
		}
		assert(prop.sp_buf_ptr != 0);

		pkt = os_channel_slot_get_packet(port->rx_ring, slot);
		assert(pkt != 0);
		if (port->user_packet_pool) {
			error = os_channel_slot_detach_packet(port->rx_ring,
			    slot, pkt);
			SKTC_ASSERT_ERR(error == 0);
		}
		buflet = os_packet_get_next_buflet(pkt, NULL);
		assert(buflet != NULL);
		bdoff = os_buflet_get_data_offset(buflet);
		buf = os_buflet_get_object_address(buflet) + bdoff;
		pkt_len = os_packet_get_data_length(pkt);
		assert(buf == (void *)prop.sp_buf_ptr);
		assert(pkt_len == prop.sp_len);
		assert(pkt_len <= frame_length);
		(void) skt_netif_ipv6_udp_frame_process(pkt, &payload,
		    sizeof(payload));
#if SKT_NETIF_DIRECT_DEBUG
		T_LOG("\nPort %d received %d bytes:\n",
		    port->port, pkt_len);
#endif
		last_slot = slot;
		if (*receive_index != payload.packet_number) {
			if (!errors_ok) {
				assert(payload.packet_number > *receive_index);
			}
			uint32_t        dropped;

			dropped = payload.packet_number - *receive_index;
			*pkts_dropped += dropped;
#if SKT_NETIF_DIRECT_DEBUG
			T_LOG(
				"child %d dropped %u (received #%u, expected #%u)\n",
				child, dropped, payload.packet_number,
				*receive_index);
#endif
			*receive_index = payload.packet_number;
		}
		if (port->user_packet_pool) {
			error = os_channel_packet_free(port->chan, pkt);
			SKTC_ASSERT_ERR(error == 0);
		}
		(*receive_count)++;
		(*receive_index)++;
		if (*receive_index == limit) {
			break;
		}
	}
	if (last_slot != NULL) {
		error = os_channel_advance_slot(port->rx_ring, last_slot);
		SKTC_ASSERT_ERR(error == 0);
		error = os_channel_sync(port->chan, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(error == 0);
	}
}

static void
skt_netif_send_and_receive(channel_port_t port, uint16_t src_port,
    struct ether_addr *dst_mac, struct in6_addr *dst_ip, uint16_t dst_port,
    uint32_t how_many, uint32_t batch_size, int child, uint32_t event_flags,
    boolean_t ifadv_enabled)
{
	int             n_events, i, error;
#define N_EVENTS_MAX    4
	struct kevent   evlist[N_EVENTS_MAX];
	struct kevent   kev[N_EVENTS_MAX];
	int             kq;
	netif_payload   payload;
	double          percent;
	boolean_t       errors_ok = FALSE;
	uint32_t        receive_packet_count;
	uint32_t        receive_packet_index;
	boolean_t       rx_complete;
	boolean_t       tx_complete;
	struct timespec timeout;
	uint32_t        pkts_dropped;
	char            ip6_str[INET6_ADDRSTRLEN];
	uint32_t        n_ifadv_events = 0, n_total_chan_events = 0;
	uint32_t        __block n_tx_expired_chan_events = 0, __block n_tx_status_chan_events = 0;
	uint64_t        __block total_tx_exp_notif_delay = 0, __block total_tx_exp_prop_delay = 0;

	assert(inet_ntop(AF_INET6, dst_ip, ip6_str, INET6_ADDRSTRLEN) != NULL);
	T_LOG("Sending to %s:%d\n", ip6_str, dst_port);
	for (i = 0; i < sizeof(payload.data); i++) {
		payload.data[i] = (uint8_t)(i & 0xff);
	}
	payload.packet_number = 0;
	kq = kqueue();
	assert(kq != -1);
	rx_complete = tx_complete = FALSE;
	receive_packet_count = 0;
	receive_packet_index = 0;
	EV_SET(kev + 0, port->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	EV_SET(kev + 1, port->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	n_events = 2;
	if ((event_flags & SKT_NETIF_DIRECT_EVFLAG_IFADV) != 0) {
		assert(n_events < N_EVENTS_MAX);
		EV_SET(kev + n_events, port->fd, EVFILT_NW_CHANNEL,
		    EV_ADD | EV_ENABLE, NOTE_IF_ADV_UPD, 0, NULL);
		n_events++;
	}
	if ((event_flags & SKT_NETIF_DIRECT_EVFLAG_CHANNEL) != 0) {
		assert(n_events < N_EVENTS_MAX);
		EV_SET(kev + n_events, port->fd, EVFILT_NW_CHANNEL,
		    EV_ADD | EV_ENABLE, NOTE_CHANNEL_EVENT, 0, NULL);
		n_events++;
		errors_ok = TRUE;
	}
	error = kevent(kq, kev, n_events, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);
	timeout.tv_sec = NETIF_TXRX_TIMEOUT_SECS;
	timeout.tv_nsec = NETIF_TXRX_TIMEOUT_NSECS;
	while (!rx_complete && !tx_complete) {
		/* wait for TX/RX/Channel events to become available */
		error = kevent(kq, NULL, 0, evlist, N_EVENTS_MAX, &timeout);
		if (error <= 0) {
			if (errno == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			/* missed seeing last few packets */
			if (!errors_ok) {
				T_LOG("child %d: timed out, TX %s "
				    "RX %s\n", child,
				    tx_complete ? "complete" :"incomplete",
				    rx_complete ? "complete" :"incomplete");
			}
			break;
		}
		for (int i = 0; i < error; i++) {
			if (evlist[i].flags & EV_ERROR) {
				int err = evlist[i].data;

				T_LOG("child %d: ev_filter %d, "
				    "flags 0x%u fflags 0x%u data %"
				    PRIxPTR "\n", child, evlist[i].filter,
				    evlist[i].flags, evlist[i].fflags,
				    evlist[i].data);
				if (err == EAGAIN) {
					break;
				}
				SKTC_ASSERT_ERR(err == 0);
			}

			switch (evlist[i].filter) {
			case EVFILT_NW_CHANNEL: {
				if ((evlist[i].fflags & NOTE_IF_ADV_UPD)
				    != 0) {
					skt_process_if_adv(port->port, port->chan);
					n_ifadv_events++;
				}
				if ((evlist[i].fflags & NOTE_CHANNEL_EVENT)
				    != 0) {
					skt_process_channel_event(port->chan,
					    NETIF_PKTID_PAYLOAD_TYPE, NETIF_PKTID_STREAM_ID,
					    ^(const os_channel_event_packet_transmit_status_t *pkt_ev) {
							n_tx_status_chan_events++;
							assert(pkt_ev->packet_status ==
							CHANNEL_EVENT_PKT_TRANSMIT_STATUS_ERR_RETRY_FAILED);
						},
					    ^(const os_channel_event_packet_transmit_expired_t *pkt_ev) {
							int64_t exp_notif_delay, exp_prop_delay;
							assert(
								(pkt_ev->packet_tx_expiration_status ==
								CHANNEL_EVENT_PKT_TRANSMIT_EXPIRED_ERR_EXPIRED_DROPPED) ||
								(pkt_ev->packet_tx_expiration_status ==
								CHANNEL_EVENT_PKT_TRANSMIT_EXPIRED_ERR_EXPIRED_NOT_DROPPED));
							n_tx_expired_chan_events++;

							exp_notif_delay = mach_absolute_time() - pkt_ev->packet_tx_expiration_timestamp;
							total_tx_exp_notif_delay += exp_notif_delay;
							exp_prop_delay = pkt_ev->packet_tx_expiration_timestamp - pkt_ev->packet_tx_expiration_deadline;
							total_tx_exp_prop_delay += exp_prop_delay;
#if SKT_COMMON_DEBUG
							T_LOG("tx_expired_event=%p "
							"code=%u "
							"deadline=%llu "
							"ts=%llu "
							"exp=%lldm %lldns "
							"notif=%lldm %lldns\n",
							pkt_ev,
							pkt_ev->packet_tx_expiration_status_code,
							pkt_ev->packet_tx_expiration_deadline,
							pkt_ev->packet_tx_expiration_timestamp,
							exp_prop_delay, SKT_NETIF_TIMESTAMP_MACH_TO_NS(exp_prop_delay),
							exp_notif_delay, SKT_NETIF_TIMESTAMP_MACH_TO_NS(exp_notif_delay));
#endif /* SKT_COMMON_DEBUG */
						},
					    NULL);
				}
				n_total_chan_events++;
				break;
			}
			case EVFILT_READ: {
				skt_netif_channel_receive(child, port,
				    how_many, &receive_packet_count,
				    &receive_packet_index, errors_ok,
				    &pkts_dropped);
				if (receive_packet_index >= how_many) {
					assert(receive_packet_index
					    == how_many);
#if SKT_NETIF_DIRECT_DEBUG
					T_LOG(
						"child %d: disable RX\n",
						child);
#endif
					EV_SET(kev, port->fd, EVFILT_READ,
					    EV_DELETE, 0, 0, NULL);
					error = kevent(kq, kev, 1,
					    NULL, 0, NULL);
					SKTC_ASSERT_ERR(error == 0);
					rx_complete = TRUE;
				}
				break;
			}
			case EVFILT_WRITE: {
				uint32_t next_batch;
				void (^packet_prehook)(packet_t p) = NULL;
				if (event_flags & SKT_NETIF_DIRECT_EVFLAG_EXPIRY) {
					packet_prehook = ^(packet_t pkt) {
						uint64_t packet_expire_time = mach_absolute_time() + expiration_deadline_mach;
						SKTC_ASSERT_ERR(os_packet_set_expire_time(pkt, packet_expire_time) == 0);
					};
				}
				next_batch = payload.packet_number + batch_size;
				if (next_batch > how_many) {
					next_batch = how_many;
				}
				skt_netif_channel_send(port, src_port, dst_mac,
				    dst_ip, dst_port, &payload, sizeof(payload),
				    next_batch, packet_prehook);
				if (payload.packet_number >= how_many) {
					assert(payload.packet_number
					    == how_many);
					T_LOG(
						"TX child %d: completed %u\n",
						child, how_many);
					tx_complete = TRUE;
#if SKT_NETIF_DIRECT_DEBUG
					T_LOG(
						"child %d: disable TX\n",
						child);
#endif
					EV_SET(kev,
					    port->fd, EVFILT_WRITE,
					    EV_DELETE, 0, 0, NULL);
					error = kevent(kq, kev, 1,
					    NULL, 0, NULL);
					SKTC_ASSERT_ERR(error == 0);
				}
				/* yield for the peer thread to read */
				usleep(1);
				break;
			}
			default:
				T_LOG("%lu event %d?\n",
				    evlist[i].ident,
				    evlist[i].filter);
				assert(0);
				break;
			}
		}
	}
	percent = 1.0 * receive_packet_count / how_many * 100.0;
	T_LOG("RX child %d: received %u (of %u) %1.02f%%\n",
	    child, receive_packet_count, how_many, percent);
	T_LOG("child %d: received %u ifadv events, %u chan events\n",
	    child, n_ifadv_events, n_total_chan_events);
	T_LOG("child %d: received %u tx status events, %u tx expired events %u total events\n",
	    child, n_tx_status_chan_events, n_tx_expired_chan_events, n_total_chan_events);

	if (n_tx_expired_chan_events > 0) {
		int64_t total_tx_exp_notif_delay_ns = SKT_NETIF_TIMESTAMP_MACH_TO_NS(total_tx_exp_notif_delay);
		int64_t total_tx_exp_prop_delay_ns = SKT_NETIF_TIMESTAMP_MACH_TO_NS(total_tx_exp_prop_delay);
		int64_t avg_tx_exp_prop_delay_ns = total_tx_exp_prop_delay_ns / n_tx_expired_chan_events;
		int64_t avg_tx_notif_delay_ns = total_tx_exp_notif_delay_ns / n_tx_expired_chan_events;
		T_LOG("child %d: expiration notification delay avg: %llu total: %llu; "
		    "expiration propagation delay avg: %llu total: %llu\n",
		    child, avg_tx_notif_delay_ns, total_tx_exp_notif_delay_ns,
		    avg_tx_exp_prop_delay_ns, total_tx_exp_prop_delay_ns);
	}

	if (!errors_ok) {
		assert(receive_packet_count > 0);
	}
	if ((event_flags & SKT_NETIF_DIRECT_EVFLAG_IFADV) != 0) {
		if (ifadv_enabled) {
			assert(n_ifadv_events != 0);
		} else {
			assert(n_ifadv_events == 0);
		}
	}
	/*
	 * If we are testing expiry events, we may face the possibility
	 * that all events were sent within the
	 * SKT_NETIF_DIRECT_TEST_EXPIRY_DEADLINE_NS interval,
	 * and therefore no expiry events have arrived.
	 * For this reason, the check for expiry events
	 * is first checking whether any event was received at all.
	 *
	 * On the other hand, the transmission status events
	 * are more deterministic, and we are not predicating the check.
	 */
	if ((event_flags & SKT_NETIF_DIRECT_EVFLAG_CHANNEL) != 0) {
		if ((event_flags & SKT_NETIF_DIRECT_EVFLAG_EXPIRY) != 0) {
			/*
			 * Check whether any events were received at all.
			 */
			if (n_total_chan_events) {
				/* We expect expiry events. */
				assert(n_tx_expired_chan_events != 0);
			}
		} else {
			/*
			 * More stringent testing for transmission status events.
			 */
			assert(n_total_chan_events != 0);
			assert(n_tx_status_chan_events != 0);
		}
	}
	close(kq);
}

int
skt_netifdirect_xfer_ipv6(int child, uint32_t test_id)
{
	struct ether_addr our_mac, peer_mac;
	struct in6_addr our_ip6, peer_ip6;
	boolean_t ifadv_enabled = FALSE;
	uint16_t our_port, peer_port;
	uint32_t event_flags = 0;
	uuid_string_t uuidstr;
	nexus_port_t nx_port;
	char buf[1] = { 0 };
	channel_port port;
	char *ifname;
	ssize_t ret;

	if (child == 0) {
		ifname = FETH0_NAME;
		sktc_get_mac_addr(FETH0_NAME, our_mac.octet);
		sktc_get_mac_addr(FETH1_NAME, peer_mac.octet);
		sktc_feth0_inet6_addr(&our_ip6);
		sktc_feth1_inet6_addr(&peer_ip6);
		our_port = FETH0_UDP_PORT;
		peer_port = FETH1_UDP_PORT;
	} else {
		assert(child == 1);
		ifname = FETH1_NAME;
		sktc_get_mac_addr(FETH1_NAME, our_mac.octet);
		sktc_get_mac_addr(FETH0_NAME, peer_mac.octet);
		sktc_feth1_inet6_addr(&our_ip6);
		sktc_feth0_inet6_addr(&peer_ip6);
		our_port = FETH1_UDP_PORT;
		peer_port = FETH0_UDP_PORT;
	}

	skt_setup_netif_with_ipv6_flow(&handles, ifname, &our_ip6, &peer_ip6,
	    &nx_port);
	sktu_channel_port_init(&port, handles.netif_nx_uuid,
	    nx_port, true,
	    (test_id == SKT_NETIF_DIRECT_TEST_CHANNEL_EVENTS || test_id == SKT_NETIF_DIRECT_TEST_EXPIRY_EVENTS) ? true : false,
	    false);
	assert(port.chan != NULL);

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_NETIF_DIRECT_DEBUG
	T_LOG("child %d signaled\n", child);
#endif

	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	port.ip6_addr = our_ip6;
	port.mac_addr = our_mac;

	uuid_unparse(handles.netif_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);
	T_LOG("child %d: Test Start\n", child);
	switch (test_id) {
	case SKT_NETIF_DIRECT_TEST_TXRX: {
		break;
	}
	case SKT_NETIF_DIRECT_TEST_IF_ADV_ENABLED: {
		event_flags |= SKT_NETIF_DIRECT_EVFLAG_IFADV;
		assert(os_channel_configure_interface_advisory(port.chan, TRUE) == 0);
		ifadv_enabled = TRUE;
		break;
	}
	case SKT_NETIF_DIRECT_TEST_IF_ADV_DISABLED: {
		event_flags |= SKT_NETIF_DIRECT_EVFLAG_IFADV;
		assert(os_channel_configure_interface_advisory(port.chan, FALSE) == 0);
		break;
	}
	case SKT_NETIF_DIRECT_TEST_CHANNEL_EVENTS: {
		event_flags |= SKT_NETIF_DIRECT_EVFLAG_CHANNEL;
		break;
	}
	case SKT_NETIF_DIRECT_TEST_EXPIRY_EVENTS: {
		event_flags |= (SKT_NETIF_DIRECT_EVFLAG_EXPIRY | SKT_NETIF_DIRECT_EVFLAG_CHANNEL);
		break;
	}
	default:
		T_LOG("unknown test id %d\n", test_id);
		assert(0);
		break;
	}
	skt_netif_send_and_receive(&port, our_port, &peer_mac, &peer_ip6,
	    peer_port, NETIF_TXRX_PACKET_COUNT, NETIF_TXRX_BATCH_COUNT,
	    child, event_flags, ifadv_enabled);
	return 0;
}

static int
skt_netifdirect_main(int argc, char *argv[])
{
	int child, test_id;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = atoi(argv[5]);

	init_expiration_deadline_mach();

	skt_netifdirect_xfer_ipv6(child, test_id);
	return 0;
}

static uint32_t skt_netif_nxctl_check;
static void
skt_netifdirect_init_native_user_access(void)
{
	uint32_t nxctl_check = 1;
	size_t len = sizeof(skt_netif_nxctl_check);

	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_netif_nxctl_check, &len,
	    &nxctl_check, sizeof(nxctl_check)) == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE |
	    FETH_FLAGS_USER_ACCESS | FETH_FLAGS_LOW_LATENCY | FETH_FLAGS_LLINK);
}

static void
skt_netifdirect_init_native_user_access_splitpools(void)
{
	uint32_t nxctl_check = 1;
	size_t len = sizeof(skt_netif_nxctl_check);

	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_netif_nxctl_check, &len,
	    &nxctl_check, sizeof(nxctl_check)) == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE |
	    FETH_FLAGS_USER_ACCESS | FETH_FLAGS_LOW_LATENCY |
	    FETH_FLAGS_LLINK | FETH_FLAGS_NONSHAREDSPLITPOOLS);
}

static void
skt_netifdirect_init_ifadv(void)
{
	int intvl = NETIF_IFADV_INTERVAL; /* in milliseconds */
	assert(sysctlbyname("net.link.fake.if_adv_intvl",
	    NULL, 0, &intvl, sizeof(intvl)) == 0);
	skt_netifdirect_init_native_user_access();
}

static void
skt_netifdirect_init_chan_events(void)
{
	int drops = NETIF_TX_PKT_DROP_RATE;
	assert(sysctlbyname("net.link.fake.tx_drops",
	    NULL, 0, &drops, sizeof(drops)) == 0);
	skt_netifdirect_init_native_user_access();
}

static void
skt_netifdirect_init_expiry_events(void)
{
	int tx_exp_policy = 1; /* IFF_TX_EXP_POLICY_DROP_AND_NOTIFY */
	assert(sysctlbyname("net.link.fake.tx_exp_policy",
	    NULL, 0, &tx_exp_policy, sizeof(tx_exp_policy)) == 0);
	skt_netifdirect_init_native_user_access();
}

static void
skt_netifdirect_fini(void)
{
	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    NULL, NULL,
	    &skt_netif_nxctl_check, sizeof(skt_netif_nxctl_check)) == 0);
	sktc_ifnet_feth_pair_destroy();
}

static void
skt_netifdirect_fini_ifadv(void)
{
	int intvl = 0; /* disable */
	assert(sysctlbyname("net.link.fake.if_adv_intvl",
	    NULL, 0, &intvl, sizeof(intvl)) == 0);
	skt_netifdirect_fini();
}

static void
skt_netifdirect_fini_chan_events(void)
{
	int drops = 0;
	assert(sysctlbyname("net.link.fake.tx_drops",
	    NULL, 0, &drops, sizeof(drops)) == 0);
	skt_netifdirect_fini();
}

static void
skt_netifdirect_fini_expiry_events(void)
{
	int tx_exp_policy = 0; /* IFF_TX_EXPN_POLICY_DISABLED */
	assert(sysctlbyname("net.link.fake.tx_exp_policy",
	    NULL, 0, &tx_exp_policy, sizeof(tx_exp_policy)) == 0);
	skt_netifdirect_fini();
}

static void
skt_netifdirect_init_native_copy_mode(void)
{
	uint32_t nxctl_check = 1;
	size_t len = sizeof(skt_netif_nxctl_check);

	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_netif_nxctl_check, &len,
	    &nxctl_check, sizeof(nxctl_check)) == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_LOW_LATENCY |
	    FETH_FLAGS_LLINK);
}

struct skywalk_mptest skt_netifdirecttxrx = {
	"netifdirecttxrx",
	"netif direct send receive test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL, STR(SKT_NETIF_DIRECT_TEST_TXRX)},
	skt_netifdirect_init_native_user_access, skt_netifdirect_fini, {},
};

struct skywalk_mptest skt_netifdirecttxrxcopymode = {
	"netifdirecttxrxcopymode",
	"netif direct send receive in copy mode test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL, STR(SKT_NETIF_DIRECT_TEST_TXRX)},
	skt_netifdirect_init_native_copy_mode, skt_netifdirect_fini, {},
};

struct skywalk_mptest skt_netifdirecttxrxsp = {
	"netifdirecttxrxsp",
	"netif direct send receive test with split rx/tx pools",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL, STR(SKT_NETIF_DIRECT_TEST_TXRX)},
	skt_netifdirect_init_native_user_access_splitpools,
	skt_netifdirect_fini, {},
};

struct skywalk_mptest skt_netifdirectifadvenable = {
	"netifdirectifadvenable",
	"netif interface advisory enabled test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_NETIF_DIRECT_TEST_IF_ADV_ENABLED)},
	skt_netifdirect_init_ifadv, skt_netifdirect_fini_ifadv, {},
};

struct skywalk_mptest skt_netifdirectifadvdisable = {
	"netifdirectifadvdisable",
	"netif interface advisory disabled test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_NETIF_DIRECT_TEST_IF_ADV_DISABLED)},
	skt_netifdirect_init_ifadv, skt_netifdirect_fini_ifadv, {},
};

struct skywalk_mptest skt_netifdirectchanevents = {
	"netifdirectchanevents",
	"netif interface channel events test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_NETIF_DIRECT_TEST_CHANNEL_EVENTS)},
	skt_netifdirect_init_chan_events, skt_netifdirect_fini_chan_events, {},
};

struct skywalk_mptest skt_netifdirectexpiryevents = {
	"netifdirectexpiryevents",
	"netif interface expiry events test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	2, skt_netifdirect_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_NETIF_DIRECT_TEST_EXPIRY_EVENTS)},
	skt_netifdirect_init_expiry_events, skt_netifdirect_fini_expiry_events, {},
};
