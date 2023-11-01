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
#include <sys/uio.h>

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
create_bpf_on_interface(const char *ifname, int *out_fd, int *out_bdlen, u_int write_size_max)
{
	int bpf_fd = -1;
	int error = 0;
	int bdlen = 0;
	u_int value;

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

	T_ASSERT_POSIX_SUCCESS(bpf_set_header_complete(bpf_fd, 1), NULL);

#ifdef BIOCSWRITEMAX
	T_ASSERT_POSIX_SUCCESS(bpf_set_write_size_max(bpf_fd, write_size_max), NULL);

	T_ASSERT_POSIX_SUCCESS(bpf_get_write_size_max(bpf_fd, &value), NULL);

	T_LOG("write_size_max %u %s value %u", write_size_max, write_size_max != value ? "!=" : "==", value);
#else
	if (write_size_max > 0) {
		T_SKIP("BIOCSWRITEMAX not supported");
	}
#endif

#ifdef BIOCSBATCHWRITE
	T_ASSERT_POSIX_SUCCESS(bpf_set_batch_write(bpf_fd, 1), NULL);

	T_ASSERT_POSIX_SUCCESS(bpf_get_batch_write(bpf_fd, &value), NULL);

	T_LOG("batch_write %u %s 1", value, value != 1 ? "!=" : "==");
#else
	T_SKIP("BIOCSBATCHWRITE not supported");
#endif

	struct timeval five_seconds = { .tv_sec = 5, .tv_usec = 0 };
	T_ASSERT_POSIX_SUCCESS(bpf_set_timeout(bpf_fd, &five_seconds), NULL);

done:
	*out_bdlen = bdlen;
	*out_fd = bpf_fd;
	return error;
}

static void
make_bootp_packet(struct iovec *iov, u_int ip_len, int id)
{
	u_int payload_len;

	if (ip_len == 0) {
		payload_len = (u_int)sizeof(dhcp_min_payload);
	} else {
		T_ASSERT_GE((size_t)ip_len, sizeof(struct ip) + sizeof(struct udphdr) + sizeof(dhcp_min_payload),
		    "ip_len");
		payload_len = ip_len - (sizeof(struct ip) + sizeof(struct udphdr));
	}

	struct ether_addr src_eaddr = {};
	ifnet_get_lladdr(udp_fd, ifname1, &src_eaddr);

	struct in_addr src_ip = { .s_addr = INADDR_ANY };
	uint16_t src_port = 68;

	struct ether_addr dst_eaddr = {};
	memset(dst_eaddr.octet, 255, ETHER_ADDR_LEN);

	struct in_addr dst_ip = { .s_addr = INADDR_BROADCAST };

	uint16_t dst_port = 67;

	void *payload = calloc(1, payload_len);

	make_dhcp_payload((dhcp_min_payload_t)payload, &src_eaddr);

	struct bootp *dhcp = (struct bootp *)payload;
	dhcp->bp_xid = (uint32_t)id;

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

	T_ASSERT_EQ(sizeof(struct bpf_hdr), BPF_WORDALIGN(sizeof(struct bpf_hdr)), "bpfhdr.bh_hdrlen == BPF_WORDALIGN(sizeof(struct bpf_hdr))");

	struct bpf_hdr bpfhdr = {};
	bpfhdr.bh_caplen = frame_length;
	bpfhdr.bh_datalen = frame_length;
	bpfhdr.bh_hdrlen = sizeof(struct bpf_hdr);

	iov->iov_len = BPF_WORDALIGN(bpfhdr.bh_hdrlen + frame_length);
	iov->iov_base = calloc(1, iov->iov_len);

	T_LOG("iov_len %lu bh_hdrlen %u frame_length %u ip_len %u payload_len %u",
	    iov->iov_len, bpfhdr.bh_hdrlen, frame_length, ip_len, payload_len);

	bcopy(&bpfhdr, iov->iov_base, bpfhdr.bh_hdrlen);
	bcopy(pkt, (char *)iov->iov_base + bpfhdr.bh_hdrlen, frame_length);

	free(pkt);
	free(payload);
}

static void
do_bpf_write_batch(int count, const char *ifname, u_int ip_len, bool expect_success, u_int write_size_max)
{
	int bpf_fd = -1;
	int bdlen = 0;
	struct iovec *iovs = NULL;
	int i;

	T_ASSERT_POSIX_ZERO(create_bpf_on_interface(ifname, &bpf_fd, &bdlen, write_size_max), NULL);
	T_LOG("bpf bdlen %d", bdlen);

	/*
	 * Allocate an iovec for each packet that contains the BPF header + the data
	 */
	iovs = calloc((size_t)count, sizeof(struct iovec));

	ssize_t total_len = 0;
	for (i = 0; i < count; i++) {
		make_bootp_packet(&iovs[i], ip_len, i + 1);
		total_len += iovs[i].iov_len;

		struct bpf_hdr *h0 = (struct bpf_hdr *)iovs[i].iov_base;;

		T_LOG("tv_sec %u tv_usec %u caplen %u datalen %u hdrlen %u",
		    h0->bh_tstamp.tv_sec, h0->bh_tstamp.tv_usec,
		    h0->bh_caplen, h0->bh_datalen, h0->bh_hdrlen);

		HexDump(iovs[i].iov_base, MIN((size_t)iovs[i].iov_len, 512));

		T_ASSERT_EQ((int)(iovs[i].iov_len % BPF_ALIGNMENT), 0, "iovs[i].iov_len %% BPF_ALIGNMENT == 0");
	}
	T_LOG("total_len %ld", total_len);

	ssize_t nwritten;
	nwritten = writev(bpf_fd, iovs, count);

	T_LOG("bpf write returned %ld", nwritten);

	if (expect_success) {
		T_ASSERT_POSIX_SUCCESS(nwritten, "write bpf");
	} else {
		T_ASSERT_POSIX_FAILURE(nwritten, EMSGSIZE, "write bpf");
		goto done;
	}

	T_LOG("bpf written %ld bytes over %lu", nwritten, total_len);

	T_ASSERT_GE((size_t)nwritten, iovs[0].iov_len, "nwritten %lu >= iovs[0].iov_len %lu", nwritten, iovs[0].iov_len);

	/*
	 * Give 100 ms for the packets to be captured
	 */
	usleep(100000);

	/*
	 * Read the batch and verify the content matches what we just sent.
	 */
	unsigned char *buffer = calloc(1, (size_t)bdlen);
	T_ASSERT_NOTNULL(buffer, "malloc()");

	ssize_t nread = read(bpf_fd, buffer, (size_t)bdlen);

	T_ASSERT_POSIX_SUCCESS(nread, "read bpf");

	T_LOG("bpf read %ld bytes", nread);

	/*
	 * We need at least the BPF header
	 */
	T_ASSERT_GT((size_t)nread, sizeof(sizeof(struct bpf_hdr)), NULL);

	unsigned char *bp = buffer;
	unsigned char *ep = buffer + nread;

	for (i = 0; i < count && bp < ep; i++) {
		struct bpf_hdr *hp = (struct bpf_hdr *)(void *)bp;

		T_LOG("tv_sec %u tv_usec %u caplen %u datalen %u hdrlen %u",
		    hp->bh_tstamp.tv_sec, hp->bh_tstamp.tv_usec,
		    hp->bh_caplen, hp->bh_datalen, hp->bh_hdrlen);

		HexDump(bp, MIN((size_t)BPF_WORDALIGN(hp->bh_hdrlen + hp->bh_caplen), 512));

		/*
		 * Note: The following will fail if there is parasitic traffic and that should not happen over feth
		 */
		unsigned char *p0 = iovs[i].iov_base;
		struct bpf_hdr *h0 = (struct bpf_hdr *)iovs[i].iov_base;;

		T_ASSERT_EQ(h0->bh_caplen, hp->bh_caplen, "h0->bh_caplen %d == hp->bh_caplen %d", h0->bh_caplen, hp->bh_caplen);
		T_ASSERT_EQ(h0->bh_datalen, hp->bh_datalen, "h0->bh_datalen %d == hp->bh_datalen %d", h0->bh_datalen, hp->bh_datalen);

		T_ASSERT_EQ_INT(bcmp(h0->bh_hdrlen + p0, hp->bh_hdrlen + bp, hp->bh_caplen), 0, "bpf read same bytes as written iov %d", i);

		bp += BPF_WORDALIGN(hp->bh_hdrlen + hp->bh_caplen);
	}

	if (buffer != NULL) {
		free(buffer);
	}
done:
	if (bpf_fd != -1) {
		close(bpf_fd);
	}
}

static void
test_bpf_write_batch(int count, u_int data_len, int mtu, bool expect_success, u_int write_size_max)
{
	init(mtu);

	T_ASSERT_POSIX_ZERO(setup_feth_pair(mtu), NULL);

	do_bpf_write_batch(count, ifname1, data_len, expect_success, write_size_max);
}

T_DECL(bpf_write_batch_dhcp, "BPF write DHCP feth MTU 1500")
{
	test_bpf_write_batch(1, 0, 1500, true, 0);
}

T_DECL(bpf_write_batch_dhcp_x2, "BPF write DHCP feth MTU 1500 x 2")
{
	test_bpf_write_batch(2, 0, 1500, true, 0);
}

T_DECL(bpf_write_batch_dhcp_x3, "BPF write DHCP feth MTU 1500 x 3")
{
	test_bpf_write_batch(3, 0, 1500, true, 0);
}

T_DECL(bpf_write_batch_1020, "BPF write 1020 feth MTU 1500 x 2")
{
	test_bpf_write_batch(2, 1020, 1500, true, 0);
}

T_DECL(bpf_write_batch_1021, "BPF write 1021 feth MTU 1500 x 2")
{
	test_bpf_write_batch(2, 1021, 1500, true, 0);
}

T_DECL(bpf_write_batch_1022, "BPF write 1022 feth MTU 1500 x 2")
{
	test_bpf_write_batch(2, 1022, 1500, true, 0);
}

T_DECL(bpf_write_batch_1023, "BPF write 1023 feth MTU 1500 x2 ")
{
	test_bpf_write_batch(2, 1023, 1500, true, 0);
}
