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
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_vlan_var.h>
#include <libkern/OSAtomic.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

/*
 ****************************************************************
 *                 Start of common section                      *
 ****************************************************************
 */
#define FILTER_RECV_PORT                20000
#define FILTER_SEND_PORT                20001

#define CMD_RECV_SOCKET_READY           0x11
#define CMD_RECV_CHANNEL_READY          0x12
#define CMD_RECV_ALL_DONE               0x13
#define CLIENT_CMD_SEND_SOCKET_START    0x21
#define CLIENT_CMD_SEND_CHANNEL_START   0x22

#define SOCKET_THREADS                  16
#define SOCKET_BYTES                    10000000
#define SOCKET_LISTENER_PORT            30000

#define CUSTOM_ETHER_THREADS            16
#define CUSTOM_ETHER_ETHERTYPE_BASE     3000
#define CUSTOM_ETHER_ITERATIONS         10000
#define CUSTOM_ETHER_PKT_LEN            512

#define SEPARATOR(opts) \
    (*(opts) != '\0' ? ", " : "")
#define SKTDBG(name, opts, fmt, ...) \
    SKD1("%s: %s%s" fmt, (name), (opts), SEPARATOR((opts)), \
    ##__VA_ARGS__)

typedef struct {
	int             fd;
	uint64_t        bytes;
} socket_args_t;

typedef struct {
	bool            is_sender;
	bool            is_tagged;
	uint16_t        ethertype;
	uint8_t         priority;
	uint64_t        sent;
	uint64_t        received;
	channel_t       ch;
	nexus_controller_t nx_ncd;
} custom_ether_args_t;

static char databuf[2048];
static socket_args_t socket_thread_args[SOCKET_THREADS];
static int socket_ready = 0;
static int socket_done = 0;

static uuid_t if_uuid;
static int custom_ether_ready = 0;
static int custom_ether_done = 0;
static ether_addr_t src_mac_addr, dst_mac_addr;
static custom_ether_args_t custom_ether_thread_args[CUSTOM_ETHER_THREADS];

static void
connect_to_server(uint16_t port, int *client_fd)
{
	struct sockaddr_in sin;
	int fd, error = 0, retries = 0;
	char *client;

	client = (port == FILTER_RECV_PORT) ? "receiver" : "sender";
	for (;;) {
		SKD1("%s: connecting to server\n", client);
		fd = socket(AF_INET, SOCK_STREAM, 0);
		SKTC_ASSERT_ERR(fd != -1);

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr("127.0.0.1");
		sin.sin_port = htons(port);
		error = connect(fd, (struct sockaddr *)&sin,
		    sizeof(sin));
		if (error == -1) {
			if (errno == ECONNREFUSED) {
				if (retries == 10) {
					SKD0("%s: giving up\n", client);
					exit(1);
				}
				(void) close(fd);
				SKD0("%s: server not ready, retrying...\n",
				    client);
				retries++;
				sleep(1);
				continue;
			} else {
				SKD0("%s: got unexpected error: %d\n",
				    client, errno);
				exit(1);
			}
		}
		SKD1("%s: connected to server\n", client);
		SKTC_ASSERT_ERR(error == 0);
		break;
	}
	*client_fd = fd;
}

static uint8_t
read_cmd(int fd)
{
	int r, error = 0;
	uint8_t cmd;

	r = read(fd, &cmd, sizeof(cmd));
	SKTC_ASSERT_ERR(r == 1);
	return cmd;
}

static void
write_cmd(int fd, uint8_t cmd)
{
	int w, error = 0;

	w = write(fd, &cmd, sizeof(cmd));
	SKTC_ASSERT_ERR(w == 1);
}

static void
wait_for_start(void)
{
	write_cmd(MPTEST_SEQ_FILENO, 0);
	(void) read_cmd(MPTEST_SEQ_FILENO);
}

static void
socket_test_status(char *name)
{
	int i;
	double total_bytes = 0, total_expected;

	total_expected = SOCKET_THREADS * SOCKET_BYTES;
	for (i = 0; i < SOCKET_THREADS; i++) {
		total_bytes += socket_thread_args[i].bytes;
	}
	SKD1("%s: %.2f%% complete\n", name,
	    (total_bytes * 100) / total_expected);
}

static void
put_packet(channel_t ch, ring_id_t ring_id, packet_t pkt)
{
	channel_ring_t tx_ring;
	channel_slot_t tx_slot = NULL;
	slot_prop_t prop;
	int error = 0;

	tx_ring = os_channel_tx_ring(ch, ring_id);
	SKTC_ASSERT_ERR(tx_ring != NULL);

	tx_slot = os_channel_get_next_slot(tx_ring, NULL, &prop);
	SKTC_ASSERT_ERR(tx_slot != NULL);

	error = os_channel_slot_attach_packet(tx_ring, tx_slot, pkt);
	SKTC_ASSERT_ERR(error == 0);

	error = os_channel_advance_slot(tx_ring, tx_slot);
	SKTC_ASSERT_ERR(error == 0);
}

static int
get_packet(channel_t ch, ring_id_t r, packet_t *pktp)
{
	int error = 0;
	slot_prop_t prop;
	channel_slot_t rx_slot, last_rx_slot = NULL;
	packet_t pkt;
	void *buf;
	buflet_t buflet;
	channel_ring_t rx_ring;

	rx_ring = os_channel_rx_ring(ch, r);
	SKTC_ASSERT_ERR(rx_ring != NULL);

	rx_slot = os_channel_get_next_slot(rx_ring, last_rx_slot, &prop);
	if (rx_slot == NULL) {
		return ENOENT;
	}
	SKTC_ASSERT_ERR(prop.sp_buf_ptr != 0);

	pkt = os_channel_slot_get_packet(rx_ring, rx_slot);
	SKTC_ASSERT_ERR(pkt != 0);

	error = os_channel_slot_detach_packet(rx_ring, rx_slot, pkt);
	SKTC_ASSERT_ERR(error == 0);

	buflet = os_packet_get_next_buflet(pkt, NULL);
	SKTC_ASSERT_ERR(buflet != NULL);

	buf = os_buflet_get_object_address(buflet);
	SKTC_ASSERT_ERR(buf != NULL);

	last_rx_slot = rx_slot;
	error = os_channel_advance_slot(rx_ring, last_rx_slot);
	SKTC_ASSERT_ERR(error == 0);

	*pktp = pkt;
	return 0;
}

static void
custom_ether_build_packet(void *buf, custom_ether_args_t *args, size_t *len)
{
	if (!args->is_tagged) {
		ether_header_t *eh = buf;

		bcopy(dst_mac_addr.octet, eh->ether_dhost, sizeof(ether_addr_t));
		bcopy(src_mac_addr.octet, eh->ether_shost, sizeof(ether_addr_t));
		eh->ether_type = htons(args->ethertype);
	} else {
		struct ether_vlan_header *evh = buf;
		uint16_t tag;

		bcopy(dst_mac_addr.octet, evh->evl_dhost, sizeof(ether_addr_t));
		bcopy(src_mac_addr.octet, evh->evl_shost, sizeof(ether_addr_t));
		evh->evl_encap_proto = htons(ETHERTYPE_VLAN);

		/* priority tag only */
		tag = args->priority << 13 & ~EVL_VLID_MASK;
		evh->evl_tag = htons(tag);
		evh->evl_proto = htons(args->ethertype);
	}

	/*
	 * TODO:
	 * Put contents here to checked by the receiver
	 */
	*len = CUSTOM_ETHER_PKT_LEN;
}

static void
custom_ether_send(channel_t ch, custom_ether_args_t *args)
{
	packet_t pkt;
	void *buf;
	size_t pkt_len;
	buflet_t buflet;
	int error;

	error = os_channel_packet_alloc(ch, &pkt);
	SKTC_ASSERT_ERR(error == 0);

	buflet = os_packet_get_next_buflet(pkt, NULL);
	SKTC_ASSERT_ERR(buflet != NULL);
	buf = os_buflet_get_object_address(buflet);
	SKTC_ASSERT_ERR(buf != NULL);

	custom_ether_build_packet(buf, args, &pkt_len);

	error = os_buflet_set_data_length(buflet, pkt_len);
	SKTC_ASSERT_ERR(error == 0);
	error = os_packet_finalize(pkt);
	SKTC_ASSERT_ERR(error == 0);

	put_packet(ch, 0, pkt);

	error = os_channel_sync(ch, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(error == 0);
	args->sent++;
}

static void
custom_ether_status(char *name, char *options)
{
	int i;
	custom_ether_args_t *args;
	double total_sent = 0, total_received = 0, total_expected;

	total_expected = CUSTOM_ETHER_THREADS * CUSTOM_ETHER_ITERATIONS;
	for (i = 0; i < CUSTOM_ETHER_THREADS; i++) {
		args = &custom_ether_thread_args[i];
		total_sent += args->sent;
		total_received += args->received;
	}
	SKTDBG(name, options, "%.2f%% sent, %.2f%% received\n",
	    (total_sent * 100) / total_expected,
	    (total_received * 100) / total_expected);
}

/*
 * XXX
 * This needs to be called outside of per-thread context because
 * closing a channel could cause a pool flush which causes packet
 * loss for unfinished threads who still have packets in flight.
 */
static void
custom_ether_cleanup(void)
{
	int i;
	custom_ether_args_t *args;

	for (i = 0; i < CUSTOM_ETHER_THREADS; i++) {
		args = &custom_ether_thread_args[i];

		if (args->ch != NULL) {
			os_channel_destroy(args->ch);
			args->ch = NULL;
		}
		if (args->nx_ncd != NULL) {
			os_nexus_controller_destroy(args->nx_ncd);
			args->nx_ncd = NULL;
		}
	}
	custom_ether_done = 0;
	custom_ether_ready = 0;
}

static bool
custom_ether_verify(packet_t pkt, custom_ether_args_t *args)
{
	buflet_t buflet;
	size_t len;
	void *buf;
	int error = 0;

	buflet = os_packet_get_next_buflet(pkt, NULL);
	SKTC_ASSERT_ERR(buflet != NULL);

	len = os_buflet_get_data_length(buflet);
	SKTC_ASSERT_ERR(len != 0);

	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	SKTC_ASSERT_ERR(buf != NULL);

	if (len != CUSTOM_ETHER_PKT_LEN) {
		SKD1("packet length mismatch: len %ld, expected %d\n",
		    len, CUSTOM_ETHER_PKT_LEN);
		return FALSE;
	}
	if (!args->is_tagged) {
		ether_header_t *eh = buf;
		uint16_t etype;

		etype = ntohs(eh->ether_type);
		if (args->ethertype != etype) {
			SKD1("ethertype mismatch: 0x%x != 0x%x\n",
			    args->ethertype, etype);
			return FALSE;
		}
	} else {
		struct ether_vlan_header *evh = buf;
		boolean_t tag_in_pkt;
		uint16_t etype, evl_tag, tag;
		int err;

		etype = ntohs(evh->evl_encap_proto);
		if (etype != ETHERTYPE_VLAN) {
			SKD1("received non-vlan packet: 0x%x", etype);
			return FALSE;
		}
		etype = ntohs(evh->evl_proto);
		if (args->ethertype != etype) {
			SKD1("ethertype mismatch: 0x%x != 0x%x\n",
			    args->ethertype, etype);
			return FALSE;
		}
		evl_tag = ntohs(evh->evl_tag);

		/* vlan tag metadata is not expected for this test case */
		err = os_packet_get_vlan_tag(pkt, &tag, &tag_in_pkt);
		if (err == 0) {
			SKD1("tag not expected: 0x%x\n", tag);
			return FALSE;
		}
		if (EVL_PRIOFTAG(evl_tag) != args->priority) {
			SKD1("priority mismatch: 0x%x != 0x%x\n",
			    EVL_PRIOFTAG(evl_tag), args->priority);
			return FALSE;
		}
	}
	return TRUE;
}

static void
custom_ether_receive(channel_t ch, custom_ether_args_t *args, packet_t pkt)
{
	bool valid;

	valid = custom_ether_verify(pkt, args);
	assert(valid);

	os_channel_packet_free(ch, pkt);
	args->received++;
}

static void
custom_ether_setup_args(int index, bool sender, bool tagged)
{
	custom_ether_args_t *args = &custom_ether_thread_args[index];

	args->is_sender = sender;
	args->is_tagged = tagged;
	if (tagged) {
		args->priority = index % 7;
	}
	args->ethertype = CUSTOM_ETHER_ETHERTYPE_BASE + index;
	args->sent = 0;
	args->received = 0;
}

static void
custom_ether_setup_flow(nexus_controller_t ncd, uuid_t uuid,
    custom_ether_args_t *args, nexus_port_t *nx_port, uuid_t bind_key)
{
	struct nx_flow_req nfr;
	uuid_t flow_uuid;
	uuid_string_t uuidstr;
	int error;

	uuid_generate(flow_uuid);
	bzero(&nfr, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_uuid);
	nfr.nfr_nx_port = NEXUS_PORT_ANY;
	nfr.nfr_ethertype = args->ethertype;
	nfr.nfr_flags |= NXFLOWREQF_CUSTOM_ETHER;

	error = __os_nexus_flow_add(ncd, uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);

	uuid_unparse(nfr.nfr_bind_key, uuidstr);
	uuid_copy(bind_key, nfr.nfr_bind_key);
	*nx_port = nfr.nfr_nx_port;
}

static void
custom_ether_handler(channel_t ch, custom_ether_args_t *args)
{
	int error;
	packet_t pkt = 0;

	error = get_packet(ch, 0, &pkt);
	assert(error == 0);
	custom_ether_receive(ch, args, pkt);
	if (args->sent < CUSTOM_ETHER_ITERATIONS) {
		custom_ether_send(ch, args);
	}
}

static void
custom_ether_thread(custom_ether_args_t *args)
{
	channel_attr_t ch_attr;
	channel_t ch;
	struct kevent evlist, kev[1];
	nexus_controller_t nx_ncd;
	nexus_port_t nx_port;
	uuid_t bind_key;
	int kq, ch_fd, error = 0;

	nx_ncd = os_nexus_controller_create();
	SKTC_ASSERT_ERR(nx_ncd != NULL);
	args->nx_ncd = nx_ncd;

	custom_ether_setup_flow(nx_ncd, if_uuid, args,
	    &nx_port, bind_key);

	ch_attr = os_channel_attr_create();
	error = os_channel_attr_set_key(ch_attr, bind_key, sizeof(bind_key));
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_attr_set(ch_attr, CHANNEL_ATTR_USER_PACKET_POOL, 1);
	SKTC_ASSERT_ERR(error == 0);

	ch = os_channel_create_extended(if_uuid, nx_port, CHANNEL_DIR_TX_RX,
	    CHANNEL_RING_ID_ANY, ch_attr);
	SKTC_ASSERT_ERR(ch != NULL);
	args->ch = ch;

	kq = kqueue();
	SKTC_ASSERT_ERR(kq != -1);

	ch_fd = os_channel_get_fd(ch);
	EV_SET(&kev[0], ch_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Increment this count to tell the main thread that we are ready */
	if (args->is_sender) {
		/* send one packet to start the test */
		custom_ether_send(ch, args);
	}
	(void) OSAtomicIncrement32(&custom_ether_ready);
	for (;;) {
		/* Wait for RX events */
		error = kevent(kq, NULL, 0, &evlist, 1, NULL);
		SKTC_ASSERT_ERR(error == 1);
		if (evlist.filter == EVFILT_READ) {
			custom_ether_handler(ch, args);
		}
		if (args->sent == CUSTOM_ETHER_ITERATIONS &&
		    args->received == CUSTOM_ETHER_ITERATIONS) {
			break;
		}
	}
	(void) OSAtomicIncrement32(&custom_ether_done);
}

/*
 ****************************************************************
 *                 End of common section                      *
 ****************************************************************
 */

/*
 ****************************************************************
 *                 Start of filter section                      *
 ****************************************************************
 */
#define FILTER_THREADS 8
static int recv_server_fd = -1;
static int send_server_fd = -1;
static int recv_client_fd = -1;
static int send_client_fd = -1;
static int32_t filter_ready = 0;

static void
filter_server_setup(uint16_t port, int *server_fd)
{
	struct sockaddr_in sin;
	int fd, flags, error = 0, on = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	SKTC_ASSERT_ERR(fd != -1);

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	SKTC_ASSERT_ERR(error == 0);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	error = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	SKTC_ASSERT_ERR(error == 0);

	error = listen(fd, 1);
	SKTC_ASSERT_ERR(error == 0);

	flags = fcntl(fd, F_GETFL, 0);
	SKTC_ASSERT_ERR(flags != -1);

	error = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	SKTC_ASSERT_ERR(error != -1);

	*server_fd = fd;
}

static void
filter_channel_setup(void)
{
	bool r;

	/* Get the interface uuid we will be adding filters to */
	r = sktc_get_netif_nexus(FETH0_NAME, if_uuid);
	assert(r);
}

static void
filter_setup(void)
{
	filter_server_setup(FILTER_RECV_PORT, &recv_server_fd);
	filter_server_setup(FILTER_SEND_PORT, &send_server_fd);
	filter_channel_setup();
}

static void
filter_wait_for_clients(void)
{
	fd_set server_fds;
	struct sockaddr_in r, s;
	socklen_t sz;
	int error = 0, maxfd;

	SKD1("filter: waiting for clients\n");
	assert(recv_server_fd != -1);
	assert(send_server_fd != -1);
	maxfd = (send_server_fd > recv_server_fd) ? send_server_fd :
	    recv_server_fd;

	for (;;) {
		FD_ZERO(&server_fds);
		if (recv_client_fd == -1) {
			FD_SET(recv_server_fd, &server_fds);
		}
		if (send_client_fd == -1) {
			FD_SET(send_server_fd, &server_fds);
		}

		error = select(maxfd + 1, &server_fds, NULL, NULL, NULL);
		SKTC_ASSERT_ERR(error != -1);

		if (FD_ISSET(recv_server_fd, &server_fds)) {
			sz = sizeof(r);
			recv_client_fd = accept(recv_server_fd,
			    (struct sockaddr *)&r, &sz);
			SKTC_ASSERT_ERR(recv_client_fd != -1);
			SKD1("filter: accepted receiver connection\n");
		} else if (FD_ISSET(send_server_fd, &server_fds)) {
			sz = sizeof(s);
			send_client_fd = accept(send_server_fd,
			    (struct sockaddr *)&s, &sz);
			SKTC_ASSERT_ERR(send_client_fd != -1);
			SKD1("filter: accepted sender connection\n");
		}
		if (recv_client_fd != -1 && send_client_fd != -1) {
			break;
		}
	}
	(void) close(recv_server_fd);
	(void) close(send_server_fd);
	recv_server_fd = -1;
	send_server_fd = -1;
}

static void
process_recv_client_cmd(void)
{
	uint8_t rcmd;

	rcmd = read_cmd(recv_client_fd);
	switch (rcmd) {
	case CMD_RECV_SOCKET_READY: {
		SKD1("filter: receiver ready to start socket test\n");

		/* Tell sender to start socket test */
		write_cmd(send_client_fd, CLIENT_CMD_SEND_SOCKET_START);
		break;
	}
	case CMD_RECV_CHANNEL_READY: {
		SKD1("filter: receiver ready to start channel test\n");

		/* Tell sender to start channel test */
		write_cmd(send_client_fd, CLIENT_CMD_SEND_CHANNEL_START);
		break;
	}
	case CMD_RECV_ALL_DONE: {
		SKD1("filter: receiver finished all tests\n");
		exit(0);
	}
	default:
		SKD0("unknown command %d\n", rcmd);
		exit(1);
	}
}

static void
process_send_client_cmd(void)
{
	/* nothing yet */
}

static int
process_ring(channel_t ch, ring_id_t r)
{
	int error, cnt = 0;
	packet_t pkt = 0;

	/*
	 * To be efficient, we process the full rx ring
	 * before calling tx sync.
	 */
	while ((error = get_packet(ch, r, &pkt)) == 0) {
		assert(pkt != 0);
		put_packet(ch, r, pkt);
		cnt++;
	}
	SKTC_ASSERT_ERR(error == ENOENT);
	if (cnt == 0) {
		return 0;
	}

	error = os_channel_sync(ch, CHANNEL_SYNC_TX);
	SKTC_ASSERT_ERR(error == 0);
	/* rx sync is done internally next time we call kevent */
	return cnt;
}

static void
filter_handler(channel_t ch)
{
	int cnt = 0;

	/*
	 * Filter packets could come in from both inbound/outbound
	 * directions. Check both RX rings.
	 */
	for (ring_id_t r = 0; r < 2; r++) {
		cnt += process_ring(ch, r);
	}
	if (cnt == 0) {
		SKD0("filter: spurious wakeup!!\n");
	}
}

static void
filter_setup_flow(nexus_controller_t ncd, uuid_t uuid,
    nexus_port_t *nx_port, uuid_t bind_key)
{
	struct nx_flow_req nfr;
	uuid_t flow_uuid;
	uuid_string_t uuidstr;
	int error;

	uuid_generate(flow_uuid);
	bzero(&nfr, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_uuid);
	nfr.nfr_nx_port = NEXUS_PORT_ANY;
	nfr.nfr_flags |= NXFLOWREQF_FILTER;

	error = __os_nexus_flow_add(ncd, uuid, &nfr);
	SKTC_ASSERT_ERR(error == 0);

	uuid_unparse(nfr.nfr_bind_key, uuidstr);
	uuid_copy(bind_key, nfr.nfr_bind_key);
	*nx_port = nfr.nfr_nx_port;
}

static void *
filter_thread(void *unused)
{
	channel_attr_t ch_attr;
	channel_t ch;
	struct kevent evlist, kev[1];
	nexus_controller_t nx_ncd;
	nexus_port_t nx_port;
	uuid_t bind_key;
	int kq, ch_fd, error = 0;

	nx_ncd = os_nexus_controller_create();
	SKTC_ASSERT_ERR(nx_ncd != NULL);
	filter_setup_flow(nx_ncd, if_uuid, &nx_port, bind_key);

	ch_attr = os_channel_attr_create();
	error = os_channel_attr_set_key(ch_attr, bind_key, sizeof(bind_key));
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_attr_set(ch_attr, CHANNEL_ATTR_USER_PACKET_POOL, 1);
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_attr_set(ch_attr, CHANNEL_ATTR_FILTER, 1);
	SKTC_ASSERT_ERR(error == 0);

	ch = os_channel_create_extended(if_uuid, nx_port, CHANNEL_DIR_TX_RX,
	    CHANNEL_RING_ID_ANY, ch_attr);
	SKTC_ASSERT_ERR(ch != NULL);

	kq = kqueue();
	SKTC_ASSERT_ERR(kq != -1);

	ch_fd = os_channel_get_fd(ch);
	EV_SET(&kev[0], ch_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	/* Increment this count to tell the main thread that we are ready */
	(void) OSAtomicIncrement32(&filter_ready);
	for (;;) {
		/* Wait for RX events */
		error = kevent(kq, NULL, 0, &evlist, 1, NULL);
		SKTC_ASSERT_ERR(error == 1);
		if (evlist.filter == EVFILT_READ) {
			filter_handler(ch);
		}
	}
	return NULL;
}

static void
filter_threads_start(void)
{
	int error, i;
	pthread_t t;

	SKD1("filter: spawning filter threads\n");
	for (i = 0; i < FILTER_THREADS; i++) {
		error = pthread_create(&t, NULL, filter_thread, NULL);
		SKTC_ASSERT_ERR(error == 0);
	}
	for (;;) {
		SKD1("filter: %d threads ready\n", filter_ready);
		if (filter_ready == FILTER_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
}

static void
filter_loop(void)
{
	fd_set client_fds;
	int maxfd;

	assert(recv_client_fd != -1);
	assert(send_client_fd != -1);
	maxfd = (send_client_fd > recv_client_fd) ? send_client_fd :
	    recv_client_fd;

	SKD1("filter: waiting for commands\n");
	for (;;) {
		FD_ZERO(&client_fds);
		FD_SET(recv_client_fd, &client_fds);
		FD_SET(send_client_fd, &client_fds);

		if (select(maxfd + 1, &client_fds, NULL, NULL, NULL) < 0) {
			SKD0("filter: select failed: %d\n", errno);
			exit(1);
		}
		if (FD_ISSET(recv_client_fd, &client_fds)) {
			process_recv_client_cmd();
		} else if (FD_ISSET(send_client_fd, &client_fds)) {
			process_send_client_cmd();
		}
	}
}

static void
filter(int testid)
{
	SKD1("filter: start\n");
	filter_setup();
	filter_wait_for_clients();
	filter_threads_start();
	filter_loop();
}
/*
 ****************************************************************
 *                 End of filter section                        *
 ****************************************************************
 */

/*
 ****************************************************************
 *                 Start of receiver section                    *
 ****************************************************************
 */

/* Used for data transfer for the socket test case */
static int receiver_fd = -1;

/* Used for sending commands to filter server */
static int receiver_client_fd = -1;

static void
receiver_socket_setup(void)
{
	struct sockaddr_in sin;
	int fd, error = 0, on = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	SKTC_ASSERT_ERR(fd != -1);

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	SKTC_ASSERT_ERR(error == 0);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(SOCKET_LISTENER_PORT);
	error = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	SKTC_ASSERT_ERR(error == 0);

	error = listen(fd, SOCKET_THREADS);
	SKTC_ASSERT_ERR(error == 0);
	receiver_fd = fd;
}

static void
receiver_channel_setup(void)
{
	int err;
	bool found;

	/* receiver uses feth0 */
	found = sktc_get_netif_nexus(FETH0_NAME, if_uuid);
	assert(found);
	err = sktc_get_mac_addr(FETH0_NAME, src_mac_addr.octet);
	assert(err == 0);
	err = sktc_get_mac_addr(FETH1_NAME, dst_mac_addr.octet);
	assert(err == 0);
}

static void
receiver_setup(void)
{
	receiver_socket_setup();
	receiver_channel_setup();
}

static void
receiver_connect_to_server(void)
{
	connect_to_server(FILTER_RECV_PORT, &receiver_client_fd);
}

static void *
receiver_socket_thread(void *arg)
{
	socket_args_t *args = arg;
	int bytes, error = 0;

	(void) OSAtomicIncrement32(&socket_ready);
	while (args->bytes < SOCKET_BYTES) {
		bytes = read(args->fd, databuf, sizeof(databuf));
		SKTC_ASSERT_ERR(bytes != -1);
		args->bytes += bytes;
	}
	(void) close(args->fd);
	(void) OSAtomicIncrement32(&socket_done);
	return NULL;
}

static void
receiver_socket_start(void)
{
	int i, fd, error = 0;
	socket_args_t *args;
	socklen_t sz;
	struct sockaddr_in sin;
	pthread_t t;

	/*
	 * The sender can connect before we spawn our threads.
	 */
	write_cmd(receiver_client_fd, CMD_RECV_SOCKET_READY);
	SKD1("receiver: spawning socket threads\n");
	for (i = 0; i < SOCKET_THREADS; i++) {
		sz = sizeof(sin);
		fd = accept(receiver_fd, (struct sockaddr *)&sin, &sz);
		SKTC_ASSERT_ERR(fd != -1);

		args = &socket_thread_args[i];
		args->fd = fd;
		args->bytes = 0;
		error = pthread_create(&t, NULL, receiver_socket_thread, args);
		SKTC_ASSERT_ERR(error == 0);
	}
	for (;;) {
		SKD1("receiver: %d socket threads ready\n", socket_ready);
		if (socket_ready == SOCKET_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
}

static void
receiver_socket_wait(void)
{
	for (;;) {
		socket_test_status("receiver");
		if (socket_done == SOCKET_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
	(void) close(receiver_fd);
	receiver_fd = -1;
}

static void *
receiver_channel_thread(void *args)
{
	custom_ether_thread(args);
	return NULL;
}

static void
receiver_channel_start(char *name, char *options, bool tagged)
{
	int error, i;
	pthread_t t;

	SKTDBG(name, options, "spawning channel threads\n");
	for (i = 0; i < CUSTOM_ETHER_THREADS; i++) {
		custom_ether_setup_args(i, false, tagged);
		error = pthread_create(&t, NULL, receiver_channel_thread,
		    &custom_ether_thread_args[i]);
		SKTC_ASSERT_ERR(error == 0);
	}
	for (;;) {
		SKTDBG(name, options, "%d channel threads ready\n",
		    custom_ether_ready);
		if (custom_ether_ready == CUSTOM_ETHER_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
	/* Tell sender we're ready */
	write_cmd(receiver_client_fd, CMD_RECV_CHANNEL_READY);
}

static void
receiver_channel_wait(char *name, char *options)
{
	for (;;) {
		custom_ether_status(name, options);
		if (custom_ether_done == CUSTOM_ETHER_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
	SKTDBG(name, options, "%d threads done\n", custom_ether_done);
	custom_ether_cleanup();
}

static void
receiver_custom_ether_test(char *name, char *options, bool tagged)
{
	receiver_channel_start(name, options, tagged);
	receiver_channel_wait(name, options);
}

static void
receiver_done(void)
{
	write_cmd(receiver_client_fd, CMD_RECV_ALL_DONE);
}

static void
receiver_start(void)
{
	receiver_socket_start();
	receiver_socket_wait();
	receiver_custom_ether_test("receiver", "", false);
	receiver_custom_ether_test("receiver", "tagged", true);
	receiver_done();
}

static void
receiver(int testid)
{
	SKD1("receiver: start\n");
	receiver_setup();
	receiver_connect_to_server();
	receiver_start();
}

/*
 ****************************************************************
 *                 End of receiver section                      *
 ****************************************************************
 */

/*
 ****************************************************************
 *                 Start of sender section                      *
 ****************************************************************
 */

/* Used for receiving commands from filter server */
static int sender_client_fd = -1;

static void
sender_socket_setup(void)
{
	/* nothing to do */
}

static void
sender_channel_setup(void)
{
	int err;
	bool found;

	/* sender uses feth1 */
	found = sktc_get_netif_nexus(FETH1_NAME, if_uuid);
	assert(found);
	err = sktc_get_mac_addr(FETH1_NAME, src_mac_addr.octet);
	assert(err == 0);
	err = sktc_get_mac_addr(FETH0_NAME, dst_mac_addr.octet);
	assert(err == 0);
}

static void
sender_setup(void)
{
	sender_socket_setup();
	sender_channel_setup();
}

static void
sender_connect_to_server(void)
{
	connect_to_server(FILTER_SEND_PORT, &sender_client_fd);
}

static void *
sender_socket_thread(void *arg)
{
	socket_args_t *args = arg;
	struct sockaddr_in sin;
	int fd, remain, bytes, ifscope, error = 0;

	(void) OSAtomicIncrement32(&socket_ready);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	SKTC_ASSERT_ERR(fd != -1);

	/* must use feth1 as outgoing interface */
	ifscope = if_nametoindex(FETH1_NAME);
	assert(ifscope != 0);
	error = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifscope,
	    sizeof(ifscope));
	SKTC_ASSERT_ERR(error == 0);

	/* connecting from feth1 to feth0 */
	sin.sin_family = AF_INET;
	sin.sin_addr = sktc_feth0_in_addr();
	sin.sin_port = htons(SOCKET_LISTENER_PORT);
	error = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
	SKTC_ASSERT_ERR(error == 0);

	remain = SOCKET_BYTES;
	while (remain > 0) {
		bytes = MIN(remain, sizeof(databuf));
		bytes = write(fd, databuf, bytes);
		SKTC_ASSERT_ERR(bytes != -1);
		remain -= bytes;
		args->bytes += bytes;
	}
	(void) close(fd);
	(void) OSAtomicIncrement32(&socket_done);
	return NULL;
}

static void
sender_socket_start(void)
{
	uint8_t cmd;
	socket_args_t *args;
	int i, error = 0;
	pthread_t t;

	/* wait for command from filter server */
	SKD1("sender: waiting for socket start command\n");
	cmd = read_cmd(sender_client_fd);
	SKTC_ASSERT_ERR(cmd == CLIENT_CMD_SEND_SOCKET_START);

	SKD1("sender: spawning socket threads\n");
	for (i = 0; i < SOCKET_THREADS; i++) {
		args = &socket_thread_args[i];
		args->fd = -1;
		args->bytes = 0;

		error = pthread_create(&t, NULL, sender_socket_thread, args);
		SKTC_ASSERT_ERR(error == 0);
	}
	for (;;) {
		SKD1("sender: %d socket threads ready\n", socket_ready);
		if (socket_ready == SOCKET_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
}

static void
sender_socket_wait(void)
{
	for (;;) {
		socket_test_status("sender");
		if (socket_done == SOCKET_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
}

static void *
sender_channel_thread(void *args)
{
	custom_ether_thread(args);
	return NULL;
}

static void
sender_channel_start(char *name, char *options, bool tagged)
{
	int error = 0, i;
	pthread_t t;
	uint8_t cmd;

	/* wait for command from filter server */
	SKTDBG(name, options, "waiting for channel start command\n");
	cmd = read_cmd(sender_client_fd);
	SKTC_ASSERT_ERR(cmd == CLIENT_CMD_SEND_CHANNEL_START);

	SKTDBG(name, options, "spawning channel threads\n");
	for (i = 0; i < CUSTOM_ETHER_THREADS; i++) {
		custom_ether_setup_args(i, true, tagged);
		error = pthread_create(&t, NULL, sender_channel_thread,
		    &custom_ether_thread_args[i]);
		SKTC_ASSERT_ERR(error == 0);
	}
	for (;;) {
		SKTDBG(name, options, "%d channel threads ready\n",
		    custom_ether_ready);
		if (custom_ether_ready == CUSTOM_ETHER_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
}

static void
sender_channel_wait(char *name, char *options)
{
	for (;;) {
		custom_ether_status(name, options);
		if (custom_ether_done == CUSTOM_ETHER_THREADS) {
			break;
		} else {
			sleep(1);
		}
	}
	SKTDBG(name, options, "%d threads done\n", custom_ether_done);
	custom_ether_cleanup();
}

static void
sender_custom_ether_test(char *name, char *options, bool tagged)
{
	sender_channel_start(name, options, tagged);
	sender_channel_wait(name, options);
}

static void
sender_start(void)
{
	sender_socket_start();
	sender_socket_wait();
	sender_custom_ether_test("sender", "", false);
	sender_custom_ether_test("sender", "tagged", true);
}

static void
sender(int testid)
{
	SKD1("sender: start\n");
	sender_setup();
	sender_connect_to_server();
	sender_start();
}
/*
 ****************************************************************
 *                 End of sender section                        *
 ****************************************************************
 */
static int
skt_filter_main(int argc, char *argv[])
{
	int child, test_id;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = 0;

	wait_for_start();
	if (child == 0) {
		filter(test_id);
	} else if (child == 1) {
		receiver(test_id);
	} else if (child == 2) {
		sender(test_id);
	}
	return 0;
}

static bool
skt_filter_supported(void)
{
	uint32_t if_attach_nx;
	size_t len = sizeof(if_attach_nx);
	bool supported;

	assert(sysctlbyname("net.link.generic.system.if_attach_nx",
	    &if_attach_nx, &len, NULL, 0) == 0);

	/* check for IF_ATTACH_NX_NETIF_NETAGENT */
	supported = ((if_attach_nx & 0x08) != 0);
	SKD1("test%ssupported, if_attach_nx=0x%x\n",
	    supported ? " " : " not ", if_attach_nx);
	return supported;
}

static uint32_t skt_netif_nxctl_check;
static void
skt_filter_init(uint32_t flags)
{
	uint32_t nxctl_check = 1;
	size_t len = sizeof(skt_netif_nxctl_check);

	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_netif_nxctl_check, &len, &nxctl_check,
	    sizeof(nxctl_check)) == 0);
	sktc_ifnet_feth_pair_create(flags);
}

static void
skt_filter_fini(void)
{
	assert(sysctlbyname("kern.skywalk.disable_nxctl_check",
	    NULL, NULL, &skt_netif_nxctl_check,
	    sizeof(skt_netif_nxctl_check)) == 0);
	sktc_ifnet_feth_pair_destroy();
}

static void
skt_filter_native_init(void)
{
	skt_filter_init(FETH_FLAGS_NATIVE | FETH_FLAGS_NXATTACH);
}

static void
skt_filter_native_fini(void)
{
	skt_filter_fini();
}

static void
skt_filter_compat_init(void)
{
	skt_filter_init(FETH_FLAGS_TXSTART | FETH_FLAGS_NXATTACH);
}

static void
skt_filter_compat_fini(void)
{
	skt_filter_fini();
}

#define NATIVE_TEST "filternative"
#define COMPAT_TEST "filtercompat"
struct skywalk_mptest skt_filternative = {
	NATIVE_TEST,
	"filter native test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	3, skt_filter_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL},
	skt_filter_native_init, skt_filter_native_fini, {},
};

struct skywalk_mptest skt_filtercompat = {
	COMPAT_TEST,
	"filter compat test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG,
	3, skt_filter_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL},
	skt_filter_compat_init, skt_filter_compat_fini, {},
};

struct skywalk_mptest_check skt_filternative_check = {
	NATIVE_TEST, skt_filter_supported,
};

struct skywalk_mptest_check skt_filtercompat_check = {
	COMPAT_TEST, skt_filter_supported,
};
