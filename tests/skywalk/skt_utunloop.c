/*
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
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

/*
 * <rdar://problem/31245751> User space forwarding for testing utun/ipsec
 *
 * A process that opens 2 channels, each one to a separate utun/ipsec interface
 * The process would then shuttle packets from one to another.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/host_reboot.h>

#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/event.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/reboot.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>

#include <arpa/inet.h> // for inet_ntop

#include <skywalk/os_skywalk.h>
#include <darwintest.h>

#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

static volatile bool g_die;

static volatile bool g_verbose;

char debugcmd[1024];

FILE *g_dumpfile;

#define VLOG(_fmt, ...)            \
	do {                                               \
	        if (g_verbose) {                                   \
	                struct timeval _stamp, _delta;                  \
	                if (!g_dumpfile) g_dumpfile = stderr;                   \
	                gettimeofday(&_stamp, NULL);                            \
	                timersub(&_stamp, &prevtime, &_delta);                                    \
	                fprintf(g_dumpfile, "% 10ld.%06d % 10ld.%06d %s: " _fmt "\n", \
	                        _stamp.tv_sec, _stamp.tv_usec,                                                  \
	                        _delta.tv_sec, _delta.tv_usec, threadname, ##__VA_ARGS__); \
	                fflush(g_dumpfile); \
	                prevtime = _stamp;                                                                                      \
	        }                                                                                                                               \
	} while (0)

static bool g_assert_stalls12;
static bool g_assert_stalls21;

static void
skt_utunloop_xfer_slots(int kq,
    channel_t rxchannel, int rxindex,
    channel_t txchannel, int txindex,
    const char *threadname, bool xfer12)
{
	int error;
	channel_ring_t rxring, txring;
	struct kevent kev;
	int rxfd, txfd;
	bool rxenable, txenable;
	time_t start, then, now;
	uint64_t slotcount, bytecount;
	uint64_t prevslotcount, prevbytecount;
	struct timeval prevtime;

	gettimeofday(&prevtime, NULL);

	rxring = os_channel_rx_ring(rxchannel, rxindex +
	    os_channel_ring_id(rxchannel, CHANNEL_FIRST_RX_RING));
	assert(rxring);
	txring = os_channel_tx_ring(txchannel, txindex +
	    os_channel_ring_id(txchannel, CHANNEL_FIRST_TX_RING));
	assert(txring);

	rxfd = os_channel_get_fd(rxchannel);
	EV_SET(&kev, rxfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);
	rxenable = true;

	txfd = os_channel_get_fd(txchannel);
	EV_SET(&kev, txfd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);
	txenable = true;

	T_LOG("thread %s has kq %d rxfd %d txfd %d\n",
	    threadname, kq, rxfd, txfd);

	prevslotcount = slotcount = 0;
	prevbytecount = bytecount = 0;
	int stallcount = 0;
	start = time(NULL);

	while (!g_die) {
		uint32_t rxavail, txavail, xfer;

		do {
			rxavail = os_channel_available_slot_count(rxring);
			txavail = os_channel_available_slot_count(txring);
			VLOG("rxavail %u txavail %u", rxavail, txavail);

			/* If there's no data to receive stop asking for output notifications
			 * but make sure that if both rx and tx are not available, that
			 * the tx remains enabled to we can wake up to reenable rx when tx
			 * eventually becomes available
			 */
			if (txenable && !rxavail && txavail) {
				EV_SET(&kev, txfd, EVFILT_WRITE, EV_DISABLE, 0, 0, NULL);
				error = kevent(kq, &kev, 1, NULL, 0, NULL);
				SKTC_ASSERT_ERR(!error);
				txenable = false;
				VLOG("txenable = false");
			} else if (!txenable && (rxavail || (!rxavail && !txavail))) {
				EV_SET(&kev, txfd, EVFILT_WRITE, EV_ENABLE, 0, 0, NULL);
				error = kevent(kq, &kev, 1, NULL, 0, NULL);
				SKTC_ASSERT_ERR(!error);
				txenable = true;
				VLOG("txenable = true");
			}

			/* If there's no place to put data, stop asking for input notifications */
			if (rxenable && !txavail) {
				EV_SET(&kev, rxfd, EVFILT_READ, EV_DISABLE, 0, 0, NULL);
				error = kevent(kq, &kev, 1, NULL, 0, NULL);
				SKTC_ASSERT_ERR(!error);
				rxenable = false;
				VLOG("rxenable = false");
			} else if (!rxenable && txavail) {
				EV_SET(&kev, rxfd, EVFILT_READ, EV_ENABLE, 0, 0, NULL);
				error = kevent(kq, &kev, 1, NULL, 0, NULL);
				SKTC_ASSERT_ERR(!error);
				rxenable = true;
				VLOG("rxenable = true");
			}

			if (!rxavail || !txavail) {
				struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};  // 1 second
				VLOG("waiting rxen %d rx %u txen %d tx %u",
				    rxenable, rxavail, txenable, txavail);

				assert(txenable || rxenable);

				error = kevent(kq, NULL, 0, &kev, 1, &timeout);
				if (error == 0) {
					//T_LOG("%s: kevent tick\n", threadname);
					if (g_die) {
						T_LOG("%s: die set, exiting\n", threadname);
						goto out;
					}
				} else {
					SKTC_ASSERT_ERR(error != -1);
					SKTC_ASSERT_ERR(error == 1);
					if (kev.filter == EVFILT_USER) {
						T_LOG("%s: user event, exiting\n",
						    threadname);
						goto out;
					} else if (kev.filter == EVFILT_WRITE) {
						VLOG("write event");
					} else if (kev.filter == EVFILT_READ) {
						VLOG("read event");
					} else {
						assert(false);
					}
				}
			}

			now = time(NULL);
			if (now > then) {
				T_LOG("%s: time %ld slotcount %llu "
				    "(total %llu) bytecount %llu (total %llu)\n",
				    threadname, now - start,
				    slotcount - prevslotcount, slotcount,
				    bytecount - prevbytecount, bytecount);

				if ((now - start) > 0 && (slotcount - prevslotcount) == 0) {
					stallcount++;
					VLOG("STALLING");
					if ((xfer12 && g_assert_stalls12) || (!xfer12 && g_assert_stalls21)) {
						if (stallcount > 2) {
							T_LOG("%s: STALLING count %d rxavail %u txavail %u\n",
							    threadname, stallcount, rxavail, txavail);
						}
						assert(stallcount < 10);
						if (stallcount == 5) {
#if 0
							reboot_np(RB_PANIC | RB_QUICK, "skt_utunloop stalled");
							host_reboot(mach_host_self(), HOST_REBOOT_DEBUGGER);
#elif 0
							if (!strcmp(threadname, "sktc_channel_worker_xfer21")) {
								T_LOG("%s: Running %s\n", threadname, debugcmd);
								pclose(popen(debugcmd, "r"));
								//system(debugcmd);
							}
//						T_LOG("%s: Sleeping\n", threadname);
//						sleep(3600000);
							T_LOG("%s: exiting because of stall\n", threadname);
							exit(252);
#elif 0
							T_LOG("%s: enabling verbose\n", threadname);
							uint64_t verbose = (1ULL << 50);
							error = sysctlbyname("kern.skywalk.verbose", NULL, NULL, &verbose, sizeof(verbose));
							SKTC_ASSERT_ERR(!error);
#endif
						}
					}
				} else {
					stallcount = 0;
				}

				then = now;
				prevslotcount = slotcount;
				prevbytecount = bytecount;
			}
		} while (!rxavail || !txavail);

#if 0
		/*
		 * Yes this distribution includes syncs with 0 slots,
		 * but that should be handled ok, so lets include it.
		 */
		xfer = arc4random_uniform(1 + MIN(txavail, rxavail));
#else
		/* IDS only transfers one slot i think */
		xfer = 1;
		//xfer = MIN(txavail,rxavail);
#endif

		VLOG("rx %u tx %u xfer %u", rxavail, txavail, xfer);

		channel_slot_t rxprev = NULL, txprev = NULL;

		for (uint32_t i = 0; i < xfer; i++) {
			slot_prop_t rxprop, txprop;
			channel_slot_t rxslot, txslot;

			rxslot = os_channel_get_next_slot(rxring, rxprev, &rxprop);
			assert(rxslot);
			txslot = os_channel_get_next_slot(txring, txprev, &txprop);
			assert(txslot);

			assert(txprop.sp_len >= rxprop.sp_len);
			memcpy((void *)txprop.sp_buf_ptr,
			    (void *)rxprop.sp_buf_ptr, rxprop.sp_len);
			txprop.sp_len = rxprop.sp_len;
			os_channel_set_slot_properties(txring, txslot, &txprop);

			slotcount += 1;
			bytecount += txprop.sp_len;

			rxprev = rxslot;
			txprev = txslot;

#if 1 // this tries to be like IDS which syncs every outgoing packet
			error = os_channel_advance_slot(txring, txprev);
			SKTC_ASSERT_ERR(!error);
			error = os_channel_sync(txchannel, CHANNEL_SYNC_TX);
			SKTC_ASSERT_ERR(!error);
			txprev = NULL;
#endif
		}

		if (txprev) {
			// If we don't sync every slot above we would do this
			error = os_channel_advance_slot(txring, txprev);
			SKTC_ASSERT_ERR(!error);
			error = os_channel_sync(txchannel, CHANNEL_SYNC_TX);
			SKTC_ASSERT_ERR(!error);
		}

		// IDS calls rx sync, so we do it here.
		error = os_channel_advance_slot(rxring, rxprev);
		SKTC_ASSERT_ERR(!error);
		error = os_channel_sync(rxchannel, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(!error);
	}

out:
	return;
}

static channel_t g_channel1, g_channel2;
static int g_kq1, g_kq2;

static void *
sktc_channel_worker_xfer12(void *ignored)
{
	pthread_setname_np(__func__);
	skt_utunloop_xfer_slots(g_kq1, g_channel1, 0, g_channel2, 0, __func__, true);
	return NULL;
}

static void *
sktc_channel_worker_xfer21(void *ignored)
{
	pthread_setname_np(__func__);
	skt_utunloop_xfer_slots(g_kq2, g_channel2, 0, g_channel1, 0, __func__, false);
	return NULL;
}

static bool
setblocking(int s, bool blocking)
{
	int error, flags;
	bool ret;
	error = fcntl(s, F_GETFL, 0);
	SKTC_ASSERT_ERR(error >= 0);
	flags = error;

	ret = !(flags & O_NONBLOCK);

	if (blocking) {
		flags &= ~O_NONBLOCK;
	} else {
		flags |= O_NONBLOCK;
	}

	T_LOG("Setting fd %d from %s to %s\n",
	    s, ret ? "blocking" : "nonblocking",
	    blocking ? "blocking" : "nonblocking");

	error = fcntl(s, F_SETFL, flags);
	SKTC_ASSERT_ERR(!error);

	return ret;
}


static int
makesocket(int type, in_addr_t addr)
{
	int error;
	int s;
	char sbuf[INET6_ADDRSTRLEN];
	struct sockaddr_in sin;

	s = socket(PF_INET, type, 0);
	assert(s != -1);

#if 0
	unsigned int ifidx;
	ifidx = if_nametoindex(ifname1); // xxx
	assert(ifidx != 0);
	error = setsockopt(s, IPPROTO_IP, IP_BOUND_IF, &ifidx, sizeof(ifidx));
	SKTC_ASSERT_ERR(!error);
#endif

	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(addr);

	error = bind(s, (struct sockaddr *)&sin, sizeof(sin));
	SKTC_ASSERT_ERR(!error);

	inet_ntop(sin.sin_family, &sin.sin_addr.s_addr, sbuf, sizeof(sbuf));
	T_LOG("%s socket %d bound to %s port %d\n",
	    type == SOCK_DGRAM ? "udp" : "tcp",
	    s, sbuf, ntohs(sin.sin_port));

	return s;
}

static void
connectsocks(int s1, int s2, bool block)
{
	int error;
	struct sockaddr_in sin;
	socklen_t slen;
	char sbuf[INET6_ADDRSTRLEN];
	bool oblock;

	slen = sizeof(sin);
	error = getsockname(s2, (struct sockaddr *)&sin, &slen);
	SKTC_ASSERT_ERR(!error);
	assert(slen <= sizeof(sin));

	oblock = setblocking(s1, block);

	inet_ntop(sin.sin_family, &sin.sin_addr.s_addr, sbuf, sizeof(sbuf));
	T_LOG("socket %d attempting to connect to %s port %d\n", s1, sbuf, ntohs(sin.sin_port));

	error = connect(s1, (struct sockaddr *)&sin, slen);
	if (block) {
		SKTC_ASSERT_ERR(!error);
	} else {
		if (error == -1 && (errno == ENETDOWN || errno == EHOSTUNREACH)) {
			SKT_LOG("socket %d waiting 1 second for net to come up (errno %d)\n",
			    s1, errno);
			sleep(1);
			error = connect(s1, (struct sockaddr *)&sin, slen);
		}
		SKTC_ASSERT_ERR(error == -1);
		SKTC_ASSERT_ERR(errno == EINPROGRESS);
	}

	setblocking(s1, oblock);

	inet_ntop(AF_INET, &sin.sin_addr.s_addr, sbuf, sizeof(sbuf));
	T_LOG("socket %d connect%s to %s port %d\n", s1,
	    block ? "ed" : "ing", sbuf, ntohs(sin.sin_port));
}

static int
acceptsock(int s)
{
	int error;
	struct sockaddr_in sin;
	socklen_t slen;
	char sbuf[INET6_ADDRSTRLEN];

	slen = sizeof(sin);
	error = accept(s, (struct sockaddr *)&sin, &slen);
	SKTC_ASSERT_ERR(error >= 0);

	inet_ntop(AF_INET, &sin.sin_addr.s_addr, sbuf, sizeof(sbuf));
	T_LOG("tcp socket %d accepted connection from %s port %d\n", error, sbuf, ntohs(sin.sin_port));

	return error;
}

#if __LP64__
#define UDPXFER                 100000 /* 100k */
#define UDPLOSSOK               3000   /* 3% */
#define UDPXFER_MEMFAIL         30000  /* 30k */
#define UDPLOSSOK_MEMFAIL       9000   /* 30% */
#define UDPPACE                 100003 /* 100us (prime) */
#else
/* On 32 bit platforms, only try to xfer 10k slots */
#define UDPXFER                 10000  /* 10k */
#define UDPLOSSOK               300    /* 3% */
#define UDPXFER_MEMFAIL         3000   /* 30k */
#define UDPLOSSOK_MEMFAIL       900    /* 30% */
#define UDPPACE                 150001 /* 150us (prime) */
#endif
#define UDPSIZE 1000

static uint32_t udpxfer;
static uint32_t udplossok;

static void *
sinkudp(void *sockfd)
{
	int s = *(int *)sockfd;
	ssize_t len;
	char buf[UDPSIZE];
	char threadname[20];
	int missed = 0;
	int readcount = 0;
	int i;
	struct timeval prevtime;

	gettimeofday(&prevtime, NULL);

	snprintf(threadname, sizeof(threadname), "%s%d", __func__, s);
	pthread_setname_np(threadname);

	assert(udpxfer != 0);

	for (i = 0; i < udpxfer; i++) {
		len = read(s, buf, sizeof(buf));
		VLOG("read %zd/%zd", len, sizeof(buf));
		if (len != sizeof(buf)) {
			SKT_LOG("%s read returned %zd errno %d count %d/%d\n",
			    threadname, len, errno, i, udpxfer);
			if (len == -1 && errno == EBADF) {
				goto out;
			}
		}
		readcount++;
		if (memcmp(buf, &i, sizeof(i))) {
			int tmp;
			memcpy(&tmp, buf, sizeof(tmp));
			if (tmp < i) {
				T_LOG("%s out of order expecting %d got %d\n",
				    threadname, i, tmp);
			}
			assert(tmp > i); // out of order will crash
			missed += tmp - i;
			i = tmp; // skip missing packets
		}
		assert(len == sizeof(buf));
	}

out:
	T_LOG("%s received %d packets, missed %d, i = %d\n",
	    threadname, readcount, missed, i);
	assert(missed <= udplossok);
	assert(readcount >= udpxfer - udplossok);

	return NULL;
}

static void *
sourceudp(void *sockfd)
{
	int s = *(int *)sockfd;
	ssize_t len;
	char buf[UDPSIZE];
	char threadname[20];
	int error;
	int kq;
	struct kevent kev;
	struct timeval prevtime;

	gettimeofday(&prevtime, NULL);

	snprintf(threadname, sizeof(threadname), "%s%d", __func__, s);
	pthread_setname_np(threadname);

	kq = kqueue();
	EV_SET(&kev, s, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);

	assert(udpxfer != 0);

	uint64_t totalloop = 0;
	uint32_t loops = 0;
	for (int i = 0; i < udpxfer; i++) {
		uint32_t loopcnt = 0;
		struct timespec ts;

		memcpy(buf, &i, sizeof(i));

		do {
			len = write(s, buf, sizeof(buf));
			VLOG("wrote %zd/%zd", len, sizeof(buf));

			/* If the very first write gets ENETDOWN, wait 1 second */
			if (i == 0 && loopcnt == 0 &&
			    len == -1 && (errno == ENETDOWN || errno == EHOSTUNREACH)) {
				SKT_LOG("%s waiting 1 second for net to come up (errno %d)\n",
				    threadname, errno);
				sleep(1);
				len = write(s, buf, sizeof(buf));
				VLOG("wrote %zd/%zd", len, sizeof(buf));
			}

			/* Wait for buffers to be available */
			if (len == -1 && errno == ENOBUFS) {
				loopcnt++;
				//T_LOG("%s waiting in kevent for buffers\n", threadname);
				error = kevent(kq, NULL, 0, &kev, 1, NULL);
				SKTC_ASSERT_ERR(error == 1);
				assert(kev.filter == EVFILT_WRITE);
				assert(kev.ident == s);
				assert(kev.udata == NULL);
				assert((kev.flags & EV_ERROR) == 0);
			} else {
				if (len != sizeof(buf)) {
					SKT_LOG("%s write returned %zd errno %d count %d/%d\n",
					    threadname, len, errno, i, udpxfer);
				}
				assert(len == sizeof(buf));
			}

			if (loopcnt > 1) {
				/* if we got ENOBUFS more than once, then sleep
				 * to avoid tight looping on write
				 */
				ts.tv_sec = 0;
				ts.tv_nsec = 1000003; // 1ms (prime)
				nanosleep(&ts, NULL);
			} else {
				ts.tv_sec = 0;
				ts.tv_nsec = UDPPACE;
				nanosleep(&ts, NULL);
			}

			/* If we're starved for a full five seconds, crash */
			if (loopcnt >= 5000) {
				T_LOG("loopcount %d\n", loopcnt);
			}
			assert(loopcnt < 5000);
		} while (len != sizeof(buf));

		/* Ideally we wouldn't get ENOBUFS immediately after getting
		 * a writable kevent.  However, these are coming from nx_netif_host
		 * when ms_classq_mbuf_to_kpkt can't allocate a packet.  In this
		 * case, flow control doesn't apply, so just tally the occurances.
		 */
		if (loopcnt > 1) {
			loops++;
			totalloop += loopcnt - 1;
			//T_LOG("%s spun in kevent %d times\n", threadname, loopcnt);
		}
	}

	error = close(kq);
	SKTC_ASSERT_ERR(!error);

	T_LOG("%s wrote %d packets, looped %u times (avg %f) exiting\n",
	    threadname, udpxfer, loops, (double)totalloop / loops);

	return NULL;
}

#if __LP64__
#define TCPXFER         100000000 /* 100mb */
#define TCPXFER_MEMFAIL 5000000   /* 5mb */
#else
#define TCPXFER         10000000  /* 10mb */
#define TCPXFER_MEMFAIL 500000    /* 0.5mb */
#endif

static uint32_t tcpxfer;

static void *
sinktcp(void *sockfd)
{
	int s = *(int *)sockfd;
	ssize_t len;
	char *buf;
	int buflen;
	socklen_t optlen;
	char threadname[20];
	int error;
	size_t nxfer;
	struct timeval prevtime;

	gettimeofday(&prevtime, NULL);

	snprintf(threadname, sizeof(threadname), "%s%d", __func__, s);
	pthread_setname_np(threadname);

	optlen = sizeof(buflen);
	error = getsockopt(s, SOL_SOCKET, SO_RCVBUF, &buflen, &optlen);
	SKTC_ASSERT_ERR(!error);

	T_LOG("%s fd %d rcvbuf size %d\n", threadname, s, buflen);

	buf = calloc(buflen, 1);
	assert(buf);

	assert(tcpxfer != 0);

	nxfer = 0;
	while (nxfer < tcpxfer) {
		size_t thisxfer = MIN(tcpxfer - nxfer, buflen);
		len = read(s, buf, thisxfer);
		VLOG("read %zd/%zd", len, thisxfer);
		//T_LOG("%s fd %d read of %zu returned %zd\n", threadname, s, thisxfer, len);
		error = len;
		SKTC_ASSERT_ERR(error != -1);
		SKTC_ASSERT_ERR(error > 0);
		SKTC_ASSERT_ERR(error <= thisxfer);
		nxfer += len;
	}

	assert(nxfer == tcpxfer);

	free(buf);

	T_LOG("%s read %zu bytes exiting\n",
	    threadname, nxfer);

	return NULL;
}


static void *
sourcetcp(void *sockfd)
{
	int s = *(int *)sockfd;
	ssize_t len;
	char *buf;
	int buflen;
	socklen_t optlen;
	char threadname[20];
	int error;
	size_t nxfer;
	struct timeval prevtime;

	gettimeofday(&prevtime, NULL);

	snprintf(threadname, sizeof(threadname), "%s%d", __func__, s);
	pthread_setname_np(threadname);

	optlen = sizeof(buflen);
	error = getsockopt(s, SOL_SOCKET, SO_SNDBUF, &buflen, &optlen);
	SKTC_ASSERT_ERR(!error);

	T_LOG("%s fd %d sndbuf size %d\n", threadname, s, buflen);

	buf = calloc(buflen, 1);
	assert(buf);

	assert(tcpxfer != 0);

	nxfer = 0;
	while (nxfer < tcpxfer) {
		size_t thisxfer = MIN(tcpxfer - nxfer, buflen);
		len = write(s, buf, thisxfer);
		VLOG("wrote %zd/%zd", len, thisxfer);

		/* If the very first write gets ENETDOWN, wait 1 second */
		if (nxfer == 0 && len == -1 &&
		    (errno == ENETDOWN || errno == EHOSTUNREACH)) {
			SKT_LOG("%s waiting 1 second for net to come up (errno %d)\n",
			    threadname, errno);
			sleep(1);
			len = write(s, buf, thisxfer);
			VLOG("wrote %zd/%zd", len, thisxfer);
		}

		//T_LOG("%s fd %d write of %zu returned %zd\n", threadname, s, thisxfer, len);
		error = len;
		SKTC_ASSERT_ERR(error == thisxfer);
		nxfer += len;
	}

	assert(nxfer == tcpxfer);

	free(buf);

	T_LOG("%s wrote %zu bytes exiting\n",
	    threadname, nxfer);

	return NULL;
}

static void
dotraffic(void *(*sourcefunc)(void *), void *(*sinkfunc)(void *),
    int sourcesock1, int sinksock2, int sourcesock2, int sinksock1)
{
	int error;
	pthread_t sinkthread1, sinkthread2;
	pthread_t sourcethread1, sourcethread2;

	assert(sourcesock1 != -1);
	assert(sinksock2 != -1);
	assert((sourcesock2 == -1) == (sinksock1 == -1));

	if (sinksock1 != -1) {
		error = pthread_create(&sinkthread1, NULL, sinkfunc, &sinksock1);
		SKTC_ASSERT_ERR(!error);
	}
	error = pthread_create(&sinkthread2, NULL, sinkfunc, &sinksock2);
	SKTC_ASSERT_ERR(!error);
	error = pthread_create(&sourcethread1, NULL, sourcefunc, &sourcesock1);
	SKTC_ASSERT_ERR(!error);
	if (sourcesock2 != -1) {
		T_LOG("waiting 1 second before starting reverse traffic\n");
		sleep(1);
		error = pthread_create(&sourcethread2, NULL, sourcefunc, &sourcesock2);
		SKTC_ASSERT_ERR(!error);
	}

	/* Wait for all data to be sent */
	error = pthread_join(sourcethread1, NULL);
	SKTC_ASSERT_ERR(!error);
	if (sourcesock2 != -1) {
		error = pthread_join(sourcethread2, NULL);
		SKTC_ASSERT_ERR(!error);
	}

	/* Give it 1 second to drain */
	T_LOG("waiting 1 second for reads to drain\n");
	sleep(1);

	/* Force the reads to exit by closing sockets */
	if (sinksock1 != -1) {
		T_LOG("closing sinksock1 %d\n", sinksock1);
		error = close(sinksock1);
		SKTC_ASSERT_ERR(!error);
	}
	T_LOG("closing sinksock2 %d\n", sinksock2);
	error = close(sinksock2);
	SKTC_ASSERT_ERR(!error);

	if (sinksock1 != -1) {
		error = pthread_join(sinkthread1, NULL);
		SKTC_ASSERT_ERR(!error);
	}
	error = pthread_join(sinkthread2, NULL);
	SKTC_ASSERT_ERR(!error);

	if (sourcesock1 != sinksock1) {
		T_LOG("closing sourcesock1 %d\n", sourcesock1);
		error = close(sourcesock1);
		SKTC_ASSERT_ERR(!error);
	}
	if (sourcesock2 != sinksock2 && sourcesock2 != -1) {
		T_LOG("closing sourcesock2 %d\n", sourcesock2);
		error = close(sourcesock2);
		SKTC_ASSERT_ERR(!error);
	}
}


static void
skt_tunloop_common(bool doutun, bool enable_netif, bool udp, bool udpduplex, bool tcp, bool tcpduplex, bool dualstream)
{
	int error;
	int utun1, utun2;
	char ifname1[IFNAMSIZ];
	char ifname2[IFNAMSIZ];
	pthread_t thread1, thread2;
	struct kevent kev;
	uint32_t memfail = 0;
	size_t len;
	int keysock;

	len = sizeof(memfail);
	if (sysctlbyname("kern.skywalk.mem.region_mtbf", &memfail, &len,
	    NULL, 0) != 0) {
		SKT_LOG("warning got errno %d getting "
		    "kern.skywalk.mem.region_mtbf: %s\n", errno,
		    strerror(errno));
	}

	if (memfail) {
		udpxfer = UDPXFER_MEMFAIL;
		udplossok = UDPLOSSOK_MEMFAIL;
		tcpxfer = TCPXFER_MEMFAIL;
	} else {
		udpxfer = UDPXFER;
		udplossok = UDPLOSSOK;
		tcpxfer = TCPXFER;
	}

	g_dumpfile = fopen(getenv("SKT_UTUNLOOP_DUMPFILE"), "w");
	if (g_dumpfile) {
		g_verbose = 1;
	}

	sktu_if_type_t type = doutun ? SKTU_IFT_UTUN : SKTU_IFT_IPSEC;
	sktu_if_flag_t flags = enable_netif ? SKTU_IFF_ENABLE_NETIF : 0;
	utun1 = sktu_create_interface(type, flags);
	utun2 = sktu_create_interface(type, flags);

	sktu_get_interface_name(type, utun1, ifname1);
	sktu_get_interface_name(type, utun2, ifname2);
	snprintf(debugcmd, sizeof(debugcmd), "netstat -qq -I %s > netstatqq.%s.txt; netstat -qq -I %s > netstatqq.%s.txt; skywalkctl netstat --flowswitch --netif > skywalkctl.txt",
	    ifname1, ifname1, ifname2, ifname2);

	uint32_t utun1addr = (10 << 24) | (getpid() & 0xffff) << 8 | 150;
	uint32_t utun2addr = utun1addr + 1;

	struct in_addr addr1, addr2, mask;
	mask  = sktc_make_in_addr(0xffffffff);
	addr1 = sktc_make_in_addr(utun1addr);
	addr2 = sktc_make_in_addr(utun2addr);

	error = sktc_ifnet_add_addr(ifname1, &addr1, &mask, &addr2);
	SKTC_ASSERT_ERR(!error);
	error = sktc_ifnet_add_addr(ifname2, &addr2, &mask, &addr1);
	SKTC_ASSERT_ERR(!error);

	if (!doutun) {
		keysock = sktu_create_pfkeysock();
		sktu_create_sa(keysock, ifname1, 12345, &addr1, &addr2);
		sktu_create_sa(keysock, ifname1, 12346, &addr2, &addr1);
		sktu_create_sa(keysock, ifname2, 12345, &addr2, &addr1);
		sktu_create_sa(keysock, ifname2, 12346, &addr1, &addr2);
	}

	g_channel1 = sktu_create_interface_channel(type, utun1);
	g_channel2 = sktu_create_interface_channel(type, utun2);

	T_LOG("Created %s and %s\n", ifname1, ifname2);

	g_kq1 = kqueue();
	EV_SET(&kev, (uintptr_t)&g_die, EVFILT_USER,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(g_kq1, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);

	g_kq2 = kqueue();
	EV_SET(&kev, (uintptr_t)&g_die, EVFILT_USER,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(g_kq2, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);

//	T_LOG("Sleeping 10 seconds at startup\n");
//	sleep(10);

	error = pthread_create(&thread1, NULL, sktc_channel_worker_xfer12, NULL);
	SKTC_ASSERT_ERR(!error);
	error = pthread_create(&thread2, NULL, sktc_channel_worker_xfer21, NULL);
	SKTC_ASSERT_ERR(!error);

	if (udp) {
		int usock1, usock2;
		usock1 = makesocket(SOCK_DGRAM, utun1addr);
		usock2 = makesocket(SOCK_DGRAM, utun2addr);
		connectsocks(usock1, usock2, true);
		connectsocks(usock2, usock1, true);
		if (udpduplex) {
			if (dualstream) {
				int usock3, usock4;
				usock3 = makesocket(SOCK_DGRAM, utun2addr);
				usock4 = makesocket(SOCK_DGRAM, utun1addr);
				connectsocks(usock3, usock4, true);
				connectsocks(usock4, usock3, true);
				dotraffic(sourceudp, sinkudp, usock1, usock2, usock3, usock4);
			} else {
				dotraffic(sourceudp, sinkudp, usock1, usock2, usock2, usock1);
			}
		} else {
			dotraffic(sourceudp, sinkudp, usock1, usock2, -1, -1);
		}
	}

	if (tcp) {
		int tsock1, tsock2, lsock; // listening socket
		tsock1 = makesocket(SOCK_STREAM, utun1addr);
		lsock = makesocket(SOCK_STREAM, utun2addr);
		error = listen(lsock, 1);
		SKTC_ASSERT_ERR(!error);
		connectsocks(tsock1, lsock, false);
		tsock2 = acceptsock(lsock);
		error = close(lsock);
		SKTC_ASSERT_ERR(!error);
		if (tcpduplex) {
			if (dualstream) {
				int tsock3, tsock4;
				tsock3 = makesocket(SOCK_STREAM, utun2addr);
				lsock = makesocket(SOCK_STREAM, utun1addr);
				error = listen(lsock, 1);
				SKTC_ASSERT_ERR(!error);
				connectsocks(tsock3, lsock, false);
				tsock4 = acceptsock(lsock);
				error = close(lsock);
				SKTC_ASSERT_ERR(!error);
				dotraffic(sourcetcp, sinktcp, tsock1, tsock2, tsock3, tsock4);
			} else {
				dotraffic(sourcetcp, sinktcp, tsock1, tsock2, tsock2, tsock1);
			}
		} else {
			dotraffic(sourcetcp, sinktcp, tsock1, tsock2, -1, -1);
		}
	}

	/* This can be useful for just setting up two utuns */
	if (!udp && !tcp) {
		sleep(1000);
	}

	/* Tell utun threads to exit */
	g_die = true;
	EV_SET(&kev, (uintptr_t)&g_die, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	error = kevent(g_kq1, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);
	EV_SET(&kev, (uintptr_t)&g_die, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	error = kevent(g_kq2, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(!error);

	error = pthread_join(thread1, NULL);
	SKTC_ASSERT_ERR(!error);
	error = pthread_join(thread2, NULL);
	SKTC_ASSERT_ERR(!error);

	os_channel_destroy(g_channel1);
	os_channel_destroy(g_channel2);

	if (!doutun) {
		error = close(keysock);
		SKTC_ASSERT_ERR(!error);
	}
	error = close(utun1);
	SKTC_ASSERT_ERR(!error);
	error = close(utun2);
	SKTC_ASSERT_ERR(!error);
}

/****************************************************************/

static int
skt_utunloopn4u1_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	skt_tunloop_common(true, false, true, false, false, false, false);
	return 0;
}

static int
skt_utunloopn4u2_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	g_assert_stalls21 = true;
	skt_tunloop_common(true, false, true, true, false, false, false);
	return 0;
}

static int
skt_utunloopn4t1_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	skt_tunloop_common(true, false, false, false, true, false, false);
	return 0;
}

static int
skt_utunloopn4t2_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	g_assert_stalls21 = true;
	skt_tunloop_common(true, false, false, false, true, true, false);
	return 0;
}

static int
skt_utunloopy4u1_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	skt_tunloop_common(true, true, true, false, false, false, false);
	return 0;
}

static int
skt_utunloopy4u2_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	g_assert_stalls21 = true;
	skt_tunloop_common(true, true, true, true, false, false, false);
	return 0;
}

static int
skt_utunloopy4t1_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	skt_tunloop_common(true, true, false, false, true, false, false);
	return 0;
}

static int
skt_utunloopy4t2_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	g_assert_stalls21 = true;
	skt_tunloop_common(true, true, false, false, true, true, false);
	return 0;
}

static int
skt_utunloopn1000_main(int argc, char *argv[])
{
	skt_tunloop_common(true, false, false, false, false, false, false);
	return 0;
}

static int
skt_utunloopy1000_main(int argc, char *argv[])
{
	skt_tunloop_common(true, true, false, false, false, false, false);
	return 0;
}

struct skywalk_test skt_utunloopn4u1 = {
	"utunloopn4u1", "open 2 utuns without netif and floods ipv4 udp packets in one direction",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopn4u1_main,
};

struct skywalk_test skt_utunloopn4u2 = {
	"utunloopn4u2", "open 2 utuns without netif and floods ipv4 udp packets in two directions",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopn4u2_main,
};

struct skywalk_test skt_utunloopn4t1 = {
	"utunloopn4t1", "open 2 utuns without netif and floods ipv4 tcp packets in one direction",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopn4t1_main,
};

struct skywalk_test skt_utunloopn4t2 = {
	"utunloopn4t2", "open 2 utuns without netif and floods ipv4 tcp packets in two directions",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopn4t2_main,
};

struct skywalk_test skt_utunloopy4u1 = {
	"utunloopy4u1", "open 2 utuns with netif and floods ipv4 udp packets in one direction",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopy4u1_main,
};

struct skywalk_test skt_utunloopy4u2 = {
	"utunloopy4u2", "open 2 utuns with netif and floods ipv4 udp packets in two directions",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopy4u2_main,
};

struct skywalk_test skt_utunloopy4t1 = {
	"utunloopy4t1", "open 2 utuns with netif and floods ipv4 tcp packets in one direction",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopy4t1_main,
};

struct skywalk_test skt_utunloopy4t2 = {
	"utunloopy4t2", "open 2 utuns with netif and floods ipv4 tcp packets in two directions",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopy4t2_main,
};

struct skywalk_test skt_utunloopn1000 = {
	"utunloopn1000", "open 2 utuns without netif and sleeps for 1000 seconds",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopn1000_main,
};

struct skywalk_test skt_utunloopy1000 = {
	"utunloopy1000", "open 2 utuns with netif and sleeps for 1000 seconds",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_utunloopy1000_main,
};

/****************************************************************/

static int
skt_ipsecloopy4u1_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	skt_tunloop_common(false, true, true, false, false, false, false);
	return 0;
}

static int
skt_ipsecloopy4u2_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	g_assert_stalls21 = true;
	skt_tunloop_common(false, true, true, true, false, false, false);
	return 0;
}

static int
skt_ipsecloopy4t1_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	skt_tunloop_common(false, true, false, false, true, false, false);
	return 0;
}

static int
skt_ipsecloopy4t2_main(int argc, char *argv[])
{
	g_assert_stalls12 = true;
	g_assert_stalls21 = true;
	skt_tunloop_common(false, true, false, false, true, true, false);
	return 0;
}

static int
skt_ipsecloopy1000_main(int argc, char *argv[])
{
	skt_tunloop_common(false, true, false, false, false, false, false);
	return 0;
}

struct skywalk_test skt_ipsecloopy4u1 = {
	"ipsecloopy4u1", "open 2 ipsecs with netif and floods ipv4 udp packets in one direction",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_ipsecloopy4u1_main,
};

struct skywalk_test skt_ipsecloopy4u2 = {
	"ipsecloopy4u2", "open 2 ipsecs with netif and floods ipv4 udp packets in two directions",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_ipsecloopy4u2_main,
};

struct skywalk_test skt_ipsecloopy4t1 = {
	"ipsecloopy4t1", "open 2 ipsecs with netif and floods ipv4 tcp packets in one direction",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_ipsecloopy4t1_main,
};

struct skywalk_test skt_ipsecloopy4t2 = {
	"ipsecloopy4t2", "open 2 ipsecs with netif and floods ipv4 tcp packets in two directions",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_ipsecloopy4t2_main,
};

struct skywalk_test skt_ipsecloopy1000 = {
	"ipsecloopy1000", "open 2 ipsecs with netif and sleeps for 1000 seconds",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_KERNEL_PIPE,
	skt_ipsecloopy1000_main,
};

/****************************************************************/
