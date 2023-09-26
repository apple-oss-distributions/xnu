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

#include <darwintest.h>

#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_fake_var.h>
#include <net/bpf.h>
#include <net/ethernet.h>

#include <netinet/ip.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "net_test_lib.h"
#include "bpflib.h"
#include "in_cksum.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));


#define MAXBUF 32
static void
HexDump(void *data, size_t len)
{
	size_t i, j, k;
	unsigned char *ptr = (unsigned char *)data;
	unsigned char buf[3 * MAXBUF + 1];

	for (i = 0; i < len; i += MAXBUF) {
		for (j = i, k = 0; j < i + MAXBUF && j < len; j++) {
			unsigned char msnbl = ptr[j] >> 4;
			unsigned char lsnbl = ptr[j] & 0x0f;

			buf[k++] = msnbl < 10 ? msnbl + '0' : msnbl + 'a' - 10;
			buf[k++] = lsnbl < 10 ? lsnbl + '0' : lsnbl + 'a' - 10;
			if ((j % 2) == 1) {
				buf[k++] = ' ';
			}
			if ((j % MAXBUF) == MAXBUF - 1) {
				buf[k++] = ' ';
			}
		}
		buf[k] = 0;
		T_LOG("%5zd: %s\n", i, buf);
	}
}

static int udp_fd = -1;
static char ifname1[IF_NAMESIZE];
static char ifname2[IF_NAMESIZE];
static int default_fake_max_mtu = 0;

static void
cleanup(void)
{
	if (udp_fd != -1) {
		(void)ifnet_destroy(udp_fd, ifname1, false);
		T_LOG("ifnet_destroy %s", ifname1);

		(void)ifnet_destroy(udp_fd, ifname2, false);
		T_LOG("ifnet_destroy %s", ifname2);
	}

	if (default_fake_max_mtu != 0) {
		T_LOG("sysctl net.link.fake.max_mtu=%d", default_fake_max_mtu);
		(void) sysctlbyname("net.link.fake.max_mtu", NULL, NULL, &default_fake_max_mtu, sizeof(int));
	}

	if (udp_fd != -1) {
		(void) close(udp_fd);
	}
}

static void
init(int mtu)
{
	T_ATEND(cleanup);

	udp_fd = inet_dgram_socket();

	if (mtu > 0) {
		size_t oldlen = sizeof(int);
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("net.link.fake.max_mtu", &default_fake_max_mtu, &oldlen, &mtu, sizeof(int)),
		    "sysctl net.link.fake.max_mtu %d -> %d", default_fake_max_mtu, mtu);
	}
}

static int
set_if_mtu(const char *ifname, int mtu)
{
	int error = 0;
	struct ifreq ifr = {};

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = mtu;

	T_ASSERT_POSIX_SUCCESS(ioctl(udp_fd, SIOCSIFMTU, (caddr_t)&ifr), NULL);

	return error;
}

static int
setup_feth_pair(int mtu)
{
	int error = 0;

	strlcpy(ifname1, FETH_NAME, sizeof(ifname1));
	error = ifnet_create_2(udp_fd, ifname1, sizeof(ifname1));
	if (error != 0) {
		goto done;
	}
	T_LOG("created %s", ifname1);

	strlcpy(ifname2, FETH_NAME, sizeof(ifname2));
	error = ifnet_create_2(udp_fd, ifname2, sizeof(ifname2));
	if (error != 0) {
		goto done;
	}
	T_LOG("created %s", ifname2);

	ifnet_attach_ip(udp_fd, ifname1);

	if ((error = fake_set_peer(udp_fd, ifname1, ifname2)) != 0) {
		goto done;
	}
	if (mtu != 0) {
		set_if_mtu(ifname1, mtu);
		set_if_mtu(ifname2, mtu);
	}
done:
	return error;
}

static int
create_bpf_on_interface(const char *ifname, int *out_fd, int *out_bdlen)
{
	int bpf_fd = -1;
	int error = 0;
	int bdlen = 0;

	bpf_fd = bpf_new();
	if (bpf_fd < 0) {
		error = errno;
		T_LOG("bpf_new");
		goto done;
	}
	T_ASSERT_POSIX_SUCCESS(bpf_set_blen(bpf_fd, 128 * 1024), NULL);

	T_ASSERT_POSIX_SUCCESS(bpf_get_blen(bpf_fd, &bdlen), NULL);

	T_ASSERT_POSIX_SUCCESS(bpf_set_immediate(bpf_fd, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, ifname), "bpf set if %s",
	    ifname1);

	T_ASSERT_POSIX_SUCCESS(bpf_set_see_sent(bpf_fd, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(bpf_set_header_complete(bpf_fd, 0), NULL);


	struct timeval five_seconds = { .tv_sec = 5, .tv_usec = 0 };
	T_ASSERT_POSIX_SUCCESS(bpf_set_timeout(bpf_fd, &five_seconds), NULL);

done:
	*out_bdlen = bdlen;
	*out_fd = bpf_fd;
	return error;
}

static void
do_bpf_write(const char *ifname, u_int ip_len, bool expect_success)
{
	int bpf_fd = -1;
	int bdlen = 0;
	u_int payload_len;

	if (ip_len == 0) {
		payload_len = (u_int)sizeof(dhcp_min_payload);
	} else {
		T_ASSERT_GE((size_t)ip_len, sizeof(struct ip) + sizeof(struct udphdr) + sizeof(dhcp_min_payload),
		    "ip_len");
		payload_len = ip_len - (sizeof(struct ip) + sizeof(struct udphdr));
	}

	T_ASSERT_POSIX_ZERO(create_bpf_on_interface(ifname, &bpf_fd, &bdlen), NULL);
	T_LOG("bpf bdlen %d", bdlen);

	struct ether_addr src_eaddr = {};
	ifnet_get_lladdr(udp_fd, ifname1, &src_eaddr);

	struct in_addr src_ip = { .s_addr = INADDR_ANY };
	uint16_t src_port = 68;

	struct ether_addr dst_eaddr = {};
	memset(dst_eaddr.octet, 255, ETHER_ADDR_LEN);

	struct in_addr dst_ip = { .s_addr = INADDR_BROADCAST };

	uint16_t dst_port = 67;

	char *payload = calloc(1, payload_len);

	make_dhcp_payload((dhcp_min_payload_t)(void *)payload, &src_eaddr);

	u_int pkt_size = ETHER_HDR_LEN + IP_MAXPACKET;
	unsigned char *pkt = calloc(1, pkt_size);

	u_int frame_length = ethernet_udp4_frame_populate((void *)pkt,
	    pkt_size,
	    &src_eaddr,
	    src_ip,
	    src_port,
	    &dst_eaddr,
	    dst_ip,
	    dst_port,
	    payload,
	    payload_len);

	T_LOG("frame_length %u ip_len %u payload_len %u", frame_length, ip_len, payload_len);

	T_ASSERT_GT((size_t)frame_length, (size_t)0, "frame_length must greater than zero");


	ssize_t nwritten;
	nwritten = write(bpf_fd, pkt, frame_length);

	T_LOG("bpf write returned %ld", nwritten);

	if (expect_success) {
		T_ASSERT_POSIX_SUCCESS(nwritten, "write bpf");
	} else {
		T_ASSERT_POSIX_FAILURE(nwritten, EMSGSIZE, "write bpf");
		goto done;
	}

	T_LOG("bpf written %ld bytes over %u", nwritten, frame_length);
	HexDump(pkt, MIN((size_t)nwritten, 256));

	unsigned char *buffer = calloc(1, (size_t)bdlen);
	T_ASSERT_NOTNULL(buffer, "malloc()");

	ssize_t nread = read(bpf_fd, buffer, (size_t)bdlen);

	T_ASSERT_POSIX_SUCCESS(nread, "read bpf");

	T_LOG("bpf read %ld bytes", nread);

	/*
	 * We need at least the BPF header
	 */
	T_ASSERT_GT((size_t)nread, sizeof(sizeof(struct bpf_hdr)), NULL);

	/*
	 * Note: The following will fail if there is parasitic traffic and that should not happen
	 */
	struct bpf_hdr *hp = (struct bpf_hdr *)(void *)buffer;
	T_LOG("tv_sec %u tv_usec %u caplen %u datalen %u hdrlen %u",
	    hp->bh_tstamp.tv_sec, hp->bh_tstamp.tv_usec,
	    hp->bh_caplen, hp->bh_datalen, hp->bh_hdrlen);

	HexDump(buffer + hp->bh_hdrlen, MIN((size_t)hp->bh_caplen, 256));

	T_ASSERT_EQ_LONG(nwritten, (long)hp->bh_caplen, "bpf read same size as written");

	T_ASSERT_EQ_INT(bcmp(buffer + hp->bh_hdrlen, pkt, (size_t)nwritten), 0, "bpf read same bytes as written");

	if (buffer != NULL) {
		free(buffer);
	}
done:
	if (bpf_fd != -1) {
		close(bpf_fd);
	}
}

static void
test_bpf_write(u_int data_len, int mtu, bool expect_success)
{
	init(mtu);

	T_ASSERT_POSIX_ZERO(setup_feth_pair(mtu), NULL);

	do_bpf_write(ifname1, data_len, expect_success);
}

T_DECL(bpf_write_dhcp, "BPF write DHCP feth MTU 1500")
{
	test_bpf_write(0, 1500, true);
}

T_DECL(bpf_write_1024, "BPF write 1024 feth MTU 1500")
{
	test_bpf_write(1024, 1500, true);
}

T_DECL(bpf_write_1514, "BPF write 1500 feth MTU 1500")
{
	test_bpf_write(1514, 1500, true);
}

T_DECL(bpf_write_65482, "BPF write 65482 feth MTU 1500")
{
	test_bpf_write(65482, 1500, false);
}

T_DECL(bpf_write_2048, "BPF write 2048 feth MTU 1500")
{
	test_bpf_write(2048, 1500, false);
}

T_DECL(bpf_write_2048_mtu_4096, "BPF write 2048 feth MTU 4096 ")
{
	test_bpf_write(2048, 4096, true);
}

T_DECL(bpf_write_4110_mtu_4096, "BPF write 4110 feth MTU 4096 ")
{
	test_bpf_write(4110, 4096, true);
}

T_DECL(bpf_write_4096_mtu_9000, "BPF write 4096 feth MTU 9000")
{
	test_bpf_write(4096, 9000, true);
}

T_DECL(bpf_write_8192_mtu_9000, "BPF write 8192 feth MTU 9000")
{
	test_bpf_write(8192, 9000, true);
}

T_DECL(bpf_write_9000_mtu_9000, "BPF write 9000 feth MTU 9000")
{
	test_bpf_write(9000, 9000, true);
}

T_DECL(bpf_write_9018_mtu_9000, "BPF write 9018 feth MTU 9000")
{
	test_bpf_write(9018, 9000, true);
}

T_DECL(bpf_write_16370_mtu_9000, "BPF write 16370 feth MTU 9000")
{
	test_bpf_write(16370, 9000, false);
}
