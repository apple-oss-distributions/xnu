/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
#include <stdlib.h>
#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <unistd.h>

#include "skywalk/skywalk_test_driver.h"
#include "skywalk/skywalk_test_common.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.skywalk"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("skywalk")
	);

#define BATS_TESTS \
	X(noop, "test just returns true") \
	X(crash, "test expects a segfault") \
	X(assert, "test verifies that assert catches failure") \
	X(features, "verifies skywalk features match kernel config") \
	X(oneslotus, "test sends one slot of data on user pipe loopback using select") \
	X(oneslotks, "test sends one slot of data on kpipe loopback using select") \
	X(oneslotup, "test sends one slot of data on user pipe loopback using poll") \
	X(oneslotkp, "test sends one slot of data on kpipe loopback using poll") \
	X(oneslotuk, "test sends one slot of data on user pipe loopback using kqueue") \
	X(oneslotkk, "test sends one slot of data on kpipe loopback using kqueue") \
	X(oneslotuk_defunct, "test sends one slot of data on user pipe loopback using kqueue with one end of the pipe defuncted") \
	X(shutdownus, "test shuts down channel on upipe and calls select") \
	X(shutdownks, "test shuts down channel on kpipe and calls select") \
	X(shutdownup, "test shuts down channel on upipe and calls poll") \
	X(shutdownkp, "test shuts down channel on kpipe and calls poll") \
	X(shutdownuk, "test shuts down channel on upipe and calls kqueue") \
	X(shutdownkk, "test shuts down channel on kpipe and calls kqueue") \
	X(shutdown2us, "test shuts down channel on upipe while in select") \
	X(shutdown2ks, "test shuts down channel on kpipe while in select") \
	X(shutdown2up, "test shuts down channel on upipe while in poll") \
	X(shutdown2kp, "test shuts down channel on kpipe while in poll") \
	X(shutdown2uk, "test shuts down channel on upipe while in kqueue") \
	X(shutdown2kk, "test shuts down channel on kpipe while in kqueue") \
	X(nslotsus, "test sends TX_SLOTS of data on user pipe loopback using select") \
	X(nslotsks, "test sends TX_SLOTS of data on kpipe loopback using select") \
	X(nslotsup, "test sends TX_SLOTS of data on user pipe loopback using poll") \
	X(nslotskp, "test sends TX_SLOTS of data on kpipe loopback using poll") \
	X(nslotsuk, "test sends TX_SLOTS of data on user pipe loopback using kqueue") \
	X(nslotskk, "test sends TX_SLOTS of data on kpipe loopback using kqueue") \
	X(mslotsus, "test sends 1000000 slots of data on user pipe loopback using select") \
	X(mslotsks, "test sends 1000000 slots of data on kpipe loopback using select") \
	X(mslotsup, "test sends 1000000 slots of data on user pipe loopback using poll") \
	X(mslotskp, "test sends 1000000 slots of data on kpipe loopback using poll") \
	X(mslotsuk, "test sends 1000000 slots of data on user pipe loopback using kqueue") \
	X(mslotskk, "test sends 1000000 slots of data on kpipe loopback using kqueue") \
	X(closecfd, "test closing guarded channel fd") \
	X(writecfd, "test writing to channel fd") \
	X(readcfd, "test reading from channel fd") \
	X(closenfd, "test closing guarded nexus fd") \
	X(readnfd, "test reading from a guarded nexus fd") \
	X(writeif, "test writes to the read only channel if") \
	X(writering, "test writes to the writeable ring") \
	X(readsmap, "test reads from the read only smap") \
	X(writesmap, "test writes to the read only smap") \
	X(verifynxadv, "test verifies nexus advisory region") \
	X(badringtl, "test calls select with bad tx ring pointers") \
	X(badringtp, "test calls poll with bad tx ring pointers") \
	X(badringtk, "test calls kqueue with bad tx ring pointers") \
	X(badringts, "test calls sync with bad tx ring pointers") \
	X(badringrl, "test calls select with bad rx ring pointers") \
	X(badringrp, "test calls poll with bad rx ring pointers") \
	X(badringrk, "test calls kqueue with bad rx ring pointers") \
	X(badringrs, "test calls sync with bad rx ring pointers") \
	X(kqueue_basic, "test kqueue return values") \
	X(kqueue_lowat_chan_bytes, "test kqueue low watermark (byte watermark on channel)") \
	X(kqueue_lowat_chan_slots, "test kqueue low watermark (slot watermark on channel)") \
	X(kqueue_lowat_note_bytes, "test kqueue low watermark (byte watermark on knote)") \
	X(kqueue_lowat_note_slots, "test kqueue low watermark (slot watermark on knote)") \
	X(change_len, "test kernel resilience to modified slot lengths") \
	X(big_len, "test unrealistically large slot lengths") \
	X(internalizemetdata, "test internalizex packet metadata verification") \
	X(ringidtx, "test opening tx ringids") \
	X(ringidrx, "test opening rx ringids") \
	X(closekqk, "test closing kqueue in kqueue") \
	X(debug_verify_u, "test confirms that skywalk is storing checksums of slots received on a upipe when in SKF_VERIFY debug mode") \
	X(utun27302538a, "test cleaning up utun kpipe while channel is in kevent (case a)") \
	X(utun27302538b, "test cleaning up utun kpipe while channel is in kevent (case b)") \
	X(utun27302538c, "test cleaning up utun kpipe while channel is in kevent (case c)") \
	X(utun27302538d, "test cleaning up utun kpipe while channel is in kevent (case d)") \
	X(bindupipeanon, "test binds a channel to an anonymous user pipe nexus") \
	X(bindupipekey, "test binds a channel to a non-anonymous user pipe nexus") \
	X(bindfswanon, "test binds a channel to an anonymous flowswitch nexus") \
	X(bindfswkey, "test binds a channel to a non-anonymous flowswitch nexus") \
	X(bindnetifkey, "test binds a channel to a non-anonymous netif nexus") \
	X(flowswitch_ns_reserve, "test confirms that flowswitches can reserve L4 ports") \
	X(flowswitch_ns_reserve2, "thorough test of netns for both BSD & flowswitch, IPv4/v6") \
	X(netifcompata, "Test setup and teardown netifcompat on feth0") \
	X(netifcompatb, "Test setup and teardown netifcompat on feth0 with deferred close channel") \
	X(netifcompatc, "Test setup and teardown netifcompat on feth0 with deferred detach and close channel") \
	X(fswloopfsw, "Test creates a flowswitch and attaches it to itself") \
	X(fswloop2ff, "Test attaches a flowswitch to a flowswitch without any netif") \
	X(teardown, "Test setup complicated topology tear it down") \
	X(teardownb, "Test setup complicated topology tear it down backwards") \
	X(fsw29301703a, "Test open 63 channels to a flowswitch") \
	X(fsw29301703b, "Test open 200 channels to a flowswitch") \
	X(fsw29301703c, "Open too many channels to a flowswitch") \
	X(fswbindany, "Test attempts to bind to port -1 of flowswitch") \
	X(fswbind0, "Test attempts to bind to port 0 of flowswitch") \
	X(fswbind1, "Test attempts to bind to port 1 of flowswitch") \
	X(fswbind512, "Test attempts to bind to port 512 of flowswitch") \
	X(fswbind2, "Test attempts to bind to port 2 of flowswitch") \
	X(fswbind5, "Test attempts to bind to port 5 of flowswitch") \
	X(fullupipe, "Test rx on full tx pipe") \
	X(upipepeerclosure, "Test channel operations on upipe with no peer") \
	X(listener, "Test skywalk listener flow creation check") \
	X(listener_stress, "Test stress skywalk listener flows") \
	X(listener_reuse, "Test stress skywalk listener reuse") \
	X(copy_cksum_single, "Test copy/checksum code: single buffer") \
	X(copy_cksum_multi, "Test copy/checksum code: buffer chain") \
	X(reass_timeout, "Test send partial fragment to flowswitch and check for ICMPv6 time exceeded reply") \
	X(reass_bad_fraglen, "Test send fragment with bad fragment length (!= 8*) to flowswitch and check for ICMPv6 param header reply") \
	X(reass_atomic, "Test send atomic ICMP echo fragment to flowswitch and check for reply") \
	X(reass_fuzz_queue_limit, "Test fuzz flowswitch to hit fragment limit") \
	X(cksum, "Test checksum code") \
	X(memory, "Test skmem allocator basic and advanced tests") \
	X(flow_req, "Test skywalk flow request api") \
	X(flow_req_ll, "Test skywalk flow request api for low latency flows") \
	X(flow_config, "Test skywalk flow config api") \
	X(flowlookup, "Test test flow lookup by send/receive of packets") \
	X(libcuckoo, "Test Cuckoo hashtable library basic and advanced tests") \
	X(restricted_port, "Test reserve a restricted ephemeral port") \
	X(steering, "Test steering rules") \
	X(listen_stress, "Test stress posix socket listen") \
	X(pllutxk, "Test send 10000000 slots to upipe sink using kqueue")

/*
 *  The following tetsts are disabled:
 *       X(writenfd, "test writing to a guarded nexus fd") due to rdar://133461652
 */

#define BATSPLL_TESTS \
	X(noop, "test just returns true") \
	X(crash, "test expects a segfault") \
	X(assert, "test verifies that assert catches failure") \
	X(features, "verifies skywalk features match kernel config") \
	X(pllutxk, "send 10000000 slots to upipe sink using kqueue") \
	X(pllutxs, "send 10000000 slots to upipe sink using select") \
	X(pllutxp, "send 10000000 slots to upipe sink using poll") \
	X(pllurxk, "receive 10000000 slots from upipe source using kqueue") \
	X(pllurxs, "receive 10000000 slots from upipe source using select") \
	X(pllurxp, "receive 10000000 slots to upipe source using poll")

#define BATSUTUN_TESTS \
	X(noop, "test just returns true") \
	X(crash, "test expects a segfault") \
	X(assert, "test verifies that assert catches failure") \
	X(features, "verifies skywalk features match kernel config") \
	X(utun27302538a, "test cleaning up utun kpipe while channel is in kevent (case a)") \
	X(utun27302538b, "test cleaning up utun kpipe while channel is in kevent (case b)") \
	X(utun27302538c, "test cleaning up utun kpipe while channel is in kevent (case c)") \
	X(utun27302538d, "test cleaning up utun kpipe while channel is in kevent (case d)") \
	X(utun27646755, "race cleaning up channel and utun socket (20 iterations)") \
	X(utunloopn4u1, "open 2 utuns without netif and floods ipv4 udp packets in one direction") \
	X(utunloopn4u2, "open 2 utuns without netif and floods ipv4 udp packets in two directions") \
	X(utunloopn4t1, "open 2 utuns without netif and floods ipv4 tcp packets in one direction") \
	X(utunloopn4t2, "open 2 utuns without netif and floods ipv4 tcp packets in two directions") \
	X(utunloopy4u1, "open 2 utuns with netif and floods ipv4 udp packets in one direction") \
	X(utunloopy4u2, "open 2 utuns with netif and floods ipv4 udp packets in two directions") \
	X(utunloopy4t1, "open 2 utuns with netif and floods ipv4 tcp packets in one direction") \
	X(utunloopy4t2, "open 2 utuns with netif and floods ipv4 tcp packets in two directions")

#define SHUTDOWN_TESTS \
	X(oneslotus, "test sends one slot of data on user pipe loopback using select") \
	X(oneslotks, "test sends one slot of data on kpipe loopback using select") \
	X(oneslotup, "test sends one slot of data on user pipe loopback using poll") \
	X(oneslotkp, "test sends one slot of data on kpipe loopback using poll") \
	X(oneslotuk, "test sends one slot of data on user pipe loopback using kqueue") \
	X(oneslotuk_defunct, "test sends one slot of data on user pipe loopback using kqueue with one end of the pipe defuncted") \
	X(oneslotkk, "test sends one slot of data on kpipe loopback using kqueue") \
	X(nslotsus, "test sends TX_SLOTS of data on user pipe loopback using select") \
	X(nslotsks, "test sends TX_SLOTS of data on kpipe loopback using select") \
	X(nslotsup, "test sends TX_SLOTS of data on user pipe loopback using poll") \
	X(nslotskp, "test sends TX_SLOTS of data on kpipe loopback using poll") \
	X(nslotsuk, "test sends TX_SLOTS of data on user pipe loopback using kqueue") \
	X(nslotskk, "test sends TX_SLOTS of data on kpipe loopback using kqueue") \
	X(mslotsus, "test sends 1000000 slots of data on user pipe loopback using select") \
	X(mslotsks, "test sends 1000000 slots of data on kpipe loopback using select") \
	X(mslotsup, "test sends 1000000 slots of data on user pipe loopback using poll") \
	X(mslotskp, "test sends 1000000 slots of data on kpipe loopback using poll") \
	X(mslotsuk, "test sends 1000000 slots of data on user pipe loopback using kqueue") \
	X(mslotskk, "test sends 1000000 slots of data on kpipe loopback using kqueue") \
	X(mmslotsus, "test sends 10000000 slots of data on user pipe loopback using select") \
	X(mmslotsks, "test sends 10000000 slots of data on kpipe loopback using select") \
	X(mmslotsup, "test sends 10000000 slots of data on user pipe loopback using poll") \
	X(mmslotskp, "test sends 10000000 slots of data on kpipe loopback using poll") \
	X(mmslotsuk, "test sends 10000000 slots of data on user pipe loopback using kqueue") \
	X(mmslotskk, "test sends 10000000 slots of data on kpipe loopback using kqueue") \
	X(closecfd, "test closing guarded channel fd") \
	X(writecfd, "test writing to channel fd") \
	X(readcfd, "test reading from channel fd") \
	X(closenfd, "test closing guarded nexus fd") \
	X(writeif, "test writes to the read only channel if") \
	X(writering, "test writes to the writeable ring") \
	X(readsmap, "test reads from the read only smap") \
	X(writesmap, "test writes to the read only smap") \
	X(verifynxadv, "test verifies nexus advisory region") \
	X(badringtl, "test calls select with bad tx ring pointers") \
	X(badringtp, "test calls poll with bad tx ring pointers") \
	X(badringtk, "test calls kqueue with bad tx ring pointers") \
	X(badringts, "test calls sync with bad tx ring pointers") \
	X(badringrl, "test calls select with bad rx ring pointers") \
	X(badringrp, "test calls poll with bad rx ring pointers") \
	X(badringrk, "test calls kqueue with bad rx ring pointers") \
	X(badringrs, "test calls sync with bad rx ring pointers") \
	X(kqueue_basic, "test kqueue return values") \
	X(kqueue_lowat_chan_slots, "test kqueue low watermark (slot watermark on channel)") \
	X(kqueue_lowat_chan_bytes, "test kqueue low watermark (byte watermark on channel)") \
	X(kqueue_lowat_note_slots, "test kqueue low watermark (slot watermark on knote)") \
	X(kqueue_lowat_note_bytes, "test kqueue low watermark (byte watermark on knote)") \
	X(change_len, "test kernel resilience to modified slot lengths") \
	X(big_len, "test unrealistically large slot lengths") \
	X(internalizemetdata, "test internalizex packet metadata verification") \
	X(ringidtx, "test opening tx ringids") \
	X(ringidrx, "test opening rx ringids") \
	X(debug_verify_u, "test confirms that skywalk is storing checksums of slots received on a upipe when in SKF_VERIFY debug mode") \
	X(debug_verify_k, "test confirms that skywalk is storing checksums of slots received on a kpipe when in SKF_VERIFY debug mode") \
	X(utun27302538a, "test cleaning up utun kpipe while channel is in kevent (case a)") \
	X(utun27302538b, "test cleaning up utun kpipe while channel is in kevent (case b)") \
	X(utun27302538c, "test cleaning up utun kpipe while channel is in kevent (case c)") \
	X(utun27302538d, "test cleaning up utun kpipe while channel is in kevent (case d)") \
	X(utun27646755, "race cleaning up channel and utun socket (20 iterations)") \
	X(utunloopn4u1, "open 2 utuns without netif and floods ipv4 udp packets in one direction") \
	X(utunloopn4u2, "open 2 utuns without netif and floods ipv4 udp packets in two directions") \
	X(utunloopn4t1, "open 2 utuns without netif and floods ipv4 tcp packets in one direction") \
	X(utunloopn4t2, "open 2 utuns without netif and floods ipv4 tcp packets in two directions") \
	X(utunloopy4u1, "open 2 utuns with netif and floods ipv4 udp packets in one direction") \
	X(utunloopy4u2, "open 2 utuns with netif and floods ipv4 udp packets in two directions") \
	X(utunloopy4t1, "open 2 utuns with netif and floods ipv4 tcp packets in one direction") \
	X(utunloopy4t2, "open 2 utuns with netif and floods ipv4 tcp packets in two directions") \
	X(ipsecloopy4u1, "open 2 ipsecs with netif and floods ipv4 udp packets in one direction") \
	X(ipsecloopy4u2, "open 2 ipsecs with netif and floods ipv4 udp packets in two directions") \
	X(ipsecloopy4t1, "open 2 ipsecs with netif and floods ipv4 tcp packets in one direction") \
	X(ipsecloopy4t2, "open 2 ipsecs with netif and floods ipv4 tcp packets in two directions") \
	X(bindupipekey, "test binds a channel to a non-anonymous user pipe nexus") \
	X(bindfswkey, "test binds a channel to a non-anonymous flowswitch nexus") \
	X(netifcompata, "Test setup and teardown netifcompat on feth0") \
	X(netifcompatb, "Test setup and teardown netifcompat on feth0 with deferred close channel") \
	X(netifcompatc, "Test setup and teardown netifcompat on feth0 with deferred detach and close channel") \
	X(teardown, "Test setup complicated topology tear it down") \
	X(teardownb, "Test setup complicated topology tear it down backwards") \
	X(teardownr, "setup complicated topology tear it down randomly (1000 iterations)") \
	X(teardownz, "setup complicated topology tear it down with each stage in an out of order position") \
	X(fsw29301703a, "Test open 63 channels to a flowswitch") \
	X(fsw29301703b, "Test open 200 channels to a flowswitch") \
	X(fsw29301703c, "Open too many channels to a flowswitch") \
	X(mf10x10, "test binds 10 ports with 10 flows per port") \
	X(mf10x100, "test binds 10 ports with 100 flows per port") \
	X(mf100x10, "test binds 100 ports with 10 flows per port") \
	X(mf100x100, "test binds 100 ports with 100 flows per port") \
	X(fullupipe, "Test rx on full tx pipe") \
	X(upipepeerclosure, "Test channel operations on upipe with no peer") \
	X(pllutxk, "send 10000000 slots to upipe sink using kqueue") \
	X(pllutxs, "send 10000000 slots to upipe sink using select") \
	X(pllutxp, "send 10000000 slots to upipe sink using poll") \
	X(pllurxk, "receive 10000000 slots from upipe source using kqueue") \
	X(pllurxs, "receive 10000000 slots from upipe source using select") \
	X(pllurxp, "receive 10000000 slots to upipe source using poll")

/*
 * These tests have failure rate > 2%, so we turn on extra logging.
 */
#define BATS_FAILING_TESTS \
	X(utunloopn4u1, "open 2 utuns without netif and floods ipv4 udp packets in one direction") \
	X(utunloopn4u2, "open 2 utuns without netif and floods ipv4 udp packets in two directions") \
	X(utunloopn4t1, "open 2 utuns without netif and floods ipv4 tcp packets in one direction") \
	X(utunloopn4t2, "open 2 utuns without netif and floods ipv4 tcp packets in two directions") \
	X(utunloopy4u1, "open 2 utuns with netif and floods ipv4 udp packets in one direction") \
	X(utunloopy4u2, "open 2 utuns with netif and floods ipv4 udp packets in two directions") \
	X(utunloopy4t1, "open 2 utuns with netif and floods ipv4 tcp packets in one direction") \
	X(utunloopy4t2, "open 2 utuns with netif and floods ipv4 tcp packets in two directions")

#define EXPAND_TO_T_DECL_COMMON(test, desc)                                    \
	{                                                                      \
	        const char *memfail_str = getenv("memfail");                   \
	        const char *ignorefail_str = getenv("ignorefail");             \
	        const char *shutdown_str = getenv("shutdown");                 \
	        const char *itersecs_str = getenv("itersecs");                 \
	        uint32_t memfail = 0;                                          \
	        bool ignorefail = false;                                       \
	        bool shutdown = false;                                         \
	        int itersecs = -1;                                             \
	        if (memfail_str) {                                             \
	                T_LOG("memfail option present: %s", memfail_str);      \
	                memfail = atoi(memfail_str);                           \
	        }                                                              \
	        if (ignorefail_str) {                                          \
	                T_LOG("ignorefail option present: %s", ignorefail_str);\
	                ignorefail = true;                                     \
	        }                                                              \
	        if (shutdown_str) {                                            \
	                T_LOG("shutdown option present: %s", shutdown_str);    \
	                shutdown = true;                                       \
	                ignorefail = true;                                     \
	        }                                                              \
	        if (itersecs_str) {                                            \
	                T_LOG("itersecs option present: %s", itersecs_str);    \
	                itersecs = atoi(itersecs_str);                         \
	        }                                                              \
	        skywalk_test_driver_run(&skt_##test, argc, (skt_##test).skt_argv,\
	            memfail, ignorefail, shutdown, itersecs);                  \
	}

/*
 * T_DECL naming convention: <testset>_<options>_<testcase>, where:
 * <testset> is one of pll or utun (we omit "bats" because it's redundant)
 * <options> is one of memfail or shutdown
 * <testcase> is the actual testcase name, such as nslotus
 */
#define EXPAND_TO_T_DECL(tdecl_name, test, desc)    \
	T_DECL(tdecl_name, desc)                    \
	EXPAND_TO_T_DECL_COMMON(test, desc)

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests bats
 */
#define X(test, desc, ...) EXPAND_TO_T_DECL(test, test, desc)
BATS_TESTS;
#undef X

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests batspll
 */
#define X(test, desc, ...) EXPAND_TO_T_DECL(pll_##test, test, desc)
BATSPLL_TESTS;
#undef X

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests batsutun
 */
#define X(test, desc, ...) EXPAND_TO_T_DECL(utun_##test, test, desc)
BATSUTUN_TESTS;
#undef X

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests --ignorefail --memfail 127 bats
 */
#define X(test, desc, ...)                                    \
	T_DECL_REF(memfail_##test, test, desc,                \
	        T_META_ENVVAR("memfail=127"),                 \
	        T_META_ENVVAR("ignorefail=true"));
BATS_TESTS;
#undef X

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests --ignorefail --memfail 127 batspll
 */
#define X(test, desc, ...)                                          \
	T_DECL_REF(pll_memfail_##test, pll_##test, desc,            \
	        T_META_ENVVAR("memfail=127"),                       \
	        T_META_ENVVAR("ignorefail=true"));
BATSPLL_TESTS;
#undef X

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests --ignorefail --memfail 127 batsutun
 */
#define X(test, desc, ...)                                              \
	T_DECL_REF(utun_memfail_##test, utun_##test, desc,              \
	        T_META_ENVVAR("memfail=127"),                           \
	        T_META_ENVVAR("ignorefail=true"));
BATSUTUN_TESTS;
#undef X

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests --memfail 0 noop
 */
T_DECL_REF(noop_memcleanup, noop, "run noop test to cleanup memory failure sysctl",
    T_META_NAMESPACE("xnu.skyawlk.memcleanup"),
    T_META_ENVVAR("memfail=0"));

/*
 * This is equivalent to the following legacy test command:
 * skywalk_tests --ignorefail --shutdown --itersecs 1 shutdown
 * Note that in the legacy test, the --itersecs option had a value of 60, but
 * here we used 1. That's because the legacy tests ran a group of tests, but here
 * it is only for a single test.
 */
#define X(test, desc, ...)                           \
	T_DECL(shutdown_##test, desc,                \
	        T_META_ENVVAR("ignorefail=true"),    \
	        T_META_ENVVAR("shutdown=true"),      \
	        T_META_ENVVAR("itersecs=1"))         \
	EXPAND_TO_T_DECL_COMMON(test, desc)
SHUTDOWN_TESTS;
#undef X

/*
 * These tests are known to have failure rate > 2% so we turn on extra logging.
 * Uncrustify does not handle T_META_MAYFAIL being used in X macros properly.
 */
/* BEGIN IGNORE CODESTYLE */
#define X(test, desc, ...)                                                \
	T_DECL(failing_##test, desc,                                      \
	        T_META_SYSCTL_INT("kern.skywalk.verbose=16492674416640"), \
	        T_META_MAYFAIL("rdar://126364642, bind call fails with EADDRNOTAVAIL")) \
        EXPAND_TO_T_DECL_COMMON(test, desc)
BATS_FAILING_TESTS;
#undef X
/* END IGNORE CODESTYLE */
