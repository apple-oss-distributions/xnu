/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 */

#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/pktsched/pktsched.h>
#include <net/classq/if_classq.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define MSEC_PER_SEC    1000            /* milliseconds per second */
static void
nsec_to_str(unsigned long long nsec, char *buf)
{
	const char *u;
	long double n = nsec, t;

	if (nsec >= NSEC_PER_SEC) {
		t = n / NSEC_PER_SEC;
		u = "sec ";
	} else if (n >= USEC_PER_SEC) {
		t = n / USEC_PER_SEC;
		u = "msec";
	} else if (n >= MSEC_PER_SEC) {
		t = n / MSEC_PER_SEC;
		u = "usec";
	} else {
		t = n;
		u = "nsec";
	}

	snprintf(buf, 32, "%-5.2Lf %4s", t, u);
}

static int
create_tun()
{
	int tun_fd;
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	memset(&kernctl_info, 0, sizeof(kernctl_info));
	strlcpy(kernctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(kernctl_info.ctl_name));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ioctl(tun_fd, CTLIOCGINFO, &kernctl_info), NULL);

	memset(&kernctl_addr, 0, sizeof(kernctl_addr));
	kernctl_addr.sc_len = sizeof(kernctl_addr);
	kernctl_addr.sc_family = AF_SYSTEM;
	kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
	kernctl_addr.sc_id = kernctl_info.ctl_id;
	kernctl_addr.sc_unit = 0;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(bind(tun_fd, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	const int enable = 1;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(setsockopt(tun_fd, SYSPROTO_CONTROL, UTUN_OPT_ENABLE_NETIF,
	    &enable, sizeof(enable)), NULL);

	T_QUIET; T_ASSERT_POSIX_FAILURE(setsockopt(tun_fd, SYSPROTO_CONTROL, UTUN_OPT_ENABLE_FLOWSWITCH,
	    &enable, sizeof(enable)), EINVAL, NULL);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(connect(tun_fd, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);;

	return tun_fd;
}

static short
ifnet_get_flags(int s, const char ifname[IFNAMSIZ])
{
	struct ifreq    ifr;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr), NULL);
	return ifr.ifr_flags;
}

static void
ifnet_add_addr4(const char ifname[IFNAMSIZ], struct in_addr *addr, struct in_addr *mask, struct in_addr *broadaddr)
{
	struct sockaddr_in *sin;
	struct in_aliasreq ifra;
	int s;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_DGRAM, 0), NULL);

	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

	if (addr != NULL) {
		sin = &ifra.ifra_addr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *addr;
	}

	if (mask != NULL) {
		sin = &ifra.ifra_mask;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *mask;
	}

	if (broadaddr != NULL || (addr != NULL &&
	    (ifnet_get_flags(s, ifname) & IFF_POINTOPOINT) != 0)) {
		sin = &ifra.ifra_broadaddr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = (broadaddr != NULL) ? *broadaddr : *addr;
	}

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(ioctl(s, SIOCAIFADDR, &ifra), NULL);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(s), NULL);
}

static struct if_qstatsreq ifqr;
static struct if_ifclassq_stats *ifcqs;
static uint32_t scheduler;

#define FQ_IF_BE_INDEX  7
static int
aqmstats_setup(char *iface)
{
	unsigned int ifindex;
	int s;

	ifindex = if_nametoindex(iface);
	T_QUIET; T_ASSERT_TRUE(ifindex != 0, "interface index for utun");

	ifcqs = malloc(sizeof(*ifcqs));
	T_ASSERT_TRUE(ifcqs != 0, "Allocated ifcqs");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_DGRAM, 0), NULL);

	bzero(&ifqr, sizeof(ifqr));
	strlcpy(ifqr.ifqr_name, iface, sizeof(ifqr.ifqr_name));
	ifqr.ifqr_buf = ifcqs;
	ifqr.ifqr_len = sizeof(*ifcqs);

	// Get the scheduler
	ifqr.ifqr_slot = 0;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGIFQUEUESTATS, (char *)&ifqr), NULL);
	scheduler = ifcqs->ifqs_scheduler;

	// Update the slot to BE
	ifqr.ifqr_slot = FQ_IF_BE_INDEX;

	return s;
}

static void
aqmstats_cleanup()
{
	free(ifcqs);
}

T_DECL(aqm_qdelay, "This test checks the min/max/avg AQM queuing delay")
{
	T_SETUPBEGIN;

	// Create tun device with IPv4 address
	int tun_fd = create_tun();

	char ifname[IFXNAMSIZ];
	socklen_t optlen = IFNAMSIZ;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(getsockopt(tun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &optlen), NULL);
	T_ASSERT_TRUE(ifname[optlen - 1] == '\0', NULL);
	T_LOG("Created interface %s", ifname);

	uint32_t ifaddr = (10 << 24) | ((unsigned)getpid() & 0xffff) << 8 | 160;
	struct in_addr tun_addr1, tun_addr2, mask;
	tun_addr1.s_addr = htonl(ifaddr);
	tun_addr2.s_addr = htonl(ifaddr + 1);
	mask.s_addr = htonl(0xffffffff);

	ifnet_add_addr4(ifname, &tun_addr1, &mask, &tun_addr2);

	// Create UDP socket to send
	int sock_fd;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sock_fd = socket(AF_INET, SOCK_DGRAM, 0), NULL);
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr = tun_addr1;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(bind(sock_fd, (struct sockaddr *)&sin, sizeof(sin)), NULL);

	struct sockaddr_in dest;
	memset(&sin, 0, sizeof(dest));
	dest.sin_len = sizeof(dest);
	dest.sin_family = AF_INET;
	dest.sin_addr = tun_addr2;
	dest.sin_port = ntohs(12345);

	// Setup the state for AQM stats
	int stats_fd = aqmstats_setup(ifname);

	T_SETUPEND;

	char min[32], max[32], avg[32];
	// Get the current value of min/max/avg qdelay
	if (scheduler == PKTSCHEDT_FQ_CODEL) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ioctl(stats_fd, SIOCGIFQUEUESTATS, (char *)&ifqr), NULL);
		nsec_to_str(ifcqs->ifqs_fq_codel_stats.fcls_min_qdelay, min);
		nsec_to_str(ifcqs->ifqs_fq_codel_stats.fcls_max_qdelay, max);
		nsec_to_str(ifcqs->ifqs_fq_codel_stats.fcls_avg_qdelay, avg);

		T_LOG("min/max/avg qdelay %10s    %10s    %10s", min, max, avg);
	}

	// Send data
	T_LOG("Sending 10 UDP packets...");
	uint8_t content[0x578] = {0};
	for (int i = 0; i < 5; i++) {
		sendto(sock_fd, content, sizeof(content), 0, (struct sockaddr *)&dest,
		    (socklen_t) sizeof(dest));
		usleep(1000);
	}

	// Get the current value of min/max/avg qdelay
	if (scheduler == PKTSCHEDT_FQ_CODEL) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ioctl(stats_fd, SIOCGIFQUEUESTATS, (char *)&ifqr), NULL);
		nsec_to_str(ifcqs->ifqs_fq_codel_stats.fcls_min_qdelay, min);
		nsec_to_str(ifcqs->ifqs_fq_codel_stats.fcls_max_qdelay, max);
		nsec_to_str(ifcqs->ifqs_fq_codel_stats.fcls_avg_qdelay, avg);

		T_LOG("min/max/avg qdelay %10s    %10s    %10s", min, max, avg);
		T_ASSERT_TRUE(ifcqs->ifqs_fq_codel_stats.fcls_min_qdelay <= ifcqs->ifqs_fq_codel_stats.fcls_avg_qdelay &&
		    ifcqs->ifqs_fq_codel_stats.fcls_min_qdelay <= ifcqs->ifqs_fq_codel_stats.fcls_max_qdelay, "min qdelay check");
		T_ASSERT_TRUE(ifcqs->ifqs_fq_codel_stats.fcls_avg_qdelay <= ifcqs->ifqs_fq_codel_stats.fcls_max_qdelay, "avg qdelay check");
	}

	aqmstats_cleanup();
	// Close socket and utun device
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(sock_fd), NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(tun_fd), NULL);
}
