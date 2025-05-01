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
#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <unistd.h>

#include "skywalk/skywalk_test_driver.h"
#include "skywalk/skywalk_test_common.h"

#define BATS_TESTS \
	X(mp100noop, "test just returns true from 100 children") \
	X(mpprotons, "test skywalk protocol namespace with two process doing conflicting reservation") \
	X(xferudp, "UDP bi-directional transfer over fake ethernet pair") \
	X(xferudpn, "UDP bi-directional transfer over native fake ethernet pair") \
	X(xferudpnsp, "UDP bi-directional transfer over native fake ethernet pair with split rx/tx pools") \
	X(xferudpfcs, "UDP bi-directional transfer over fake ethernet pair with link frame check sequence") \
	X(xferudptrailer, "UDP bi-directional transfer over fake ethernet pair with link trailer") \
	X(xferudpnfcs, "UDP bi-directional transfer over native fake ethernet pair with link frame check sequence") \
	X(xferudpntrailer, "UDP bi-directional transfer over native fake ethernet pair with link trailer") \
	X(xferudpoverwhelm, "UDP bi-directional transfer over fake ethernet pair overwhelm") \
	X(xferudpoverwhelmn, "UDP bi-directional transfer over native fake ethernet pair overwhelm") \
	X(xferudpoverwhelmnsp, "UDP bi-directional transfer over native fake ethernet pair overwhelm with split rx/tx pools") \
	X(xferudpping, "UDP ping-pong over fake ethernet pair") \
	X(xferudppingn, "UDP ping-pong over native fake ethernet pair") \
	X(xferudpping1, "UDP ping-pong once over fake ethernet pair") \
	X(xferudpping1n, "UDP ping-pong once over native fake ethernet pair") \
	X(xferudpping1wrong, "UDP ping-pong once over fake ethernet pair with wrong flow IDs") \
	X(xfertcpsynflood, "TCP SYN flood") \
	X(xfertcprstflood, "TCP RST flood") \
	X(xferudpwitherrors, "UDP bi-directional transfer over native fake ethernet pair with injected errors") \
	X(xferudpwitherrorscompat, "UDP bi-directional transfer over compat fake ethernet pair with injected errors") \
	X(xferudpping_aqm, "UDP ping-pong over fake ethernet pair with AQM") \
	X(xferudppingn_aqm, "UDP ping-pong over native fake ethernet pair with AQM") \
	X(xfertcpportzero, "TCP connect to port 0") \
	X(xferudpportzero, "UDP connect to port 0") \
	X(xfersetuponly, "setup fake ethernet pair only") \
	X(xfersetuponlyn, "setup native fake ethernet pair only") \
	X(xferudppingn_wmm, "UDP ping-pong over native fake ethernet pair in wmm mode") \
	X(xferflowmatch, "Packets not matching registered flow tuple should be dropped") \
	X(xferflowcleanup, "verification of flow cleanup on channel close") \
	X(xferudppingn_mb, "UDP ping-pong over native fake ethernet pair with multi-buflet packet") \
	X(xferfastlane, "fastlane qos marking") \
	X(xferfastlanen, "fastlane qos marking over native") \
	X(xferrfc4594, "rfc4594 qos marking") \
	X(xferrfc4594n, "rfc4594 qos marking over native") \
	X(xfercsumoffload, "Packet checksum offload") \
	X(xfercsumoffloadn, "Packet checksum offload over native") \
	X(xferudpfrags, "UDP fragmentation test (channel flow Tx)") \
	X(xferudpbadfrags, "UDP fragmentation test (channel flow Tx)") \
	X(xferlistenertcprst, "TCP Listner should be able to send RST") \
	X(netifdirecttxrx, "netif direct send receive test") \
	X(netifdirecttxrxsp, "netif direct send receive test with split rx/tx pools") \
	X(netifdirectifadvdisable, "netif interface advisory disabled test") \
	X(netifdirectchanevents, "netif interface channel events test") \
	X(netifdirectexpiryevents, "netif interface expiry events test") \
	X(xferudpifadvenable, "flowswitch interface advisory enabled test") \
	X(xferudpifadvdisable, "flowswitch interface advisory disabled test") \
	X(xferudpchanevents, "flowswitch channel events test") \
	X(xferudpchaneventsasync, "flowswitch channel events in async mode test") \
	X(xferudppingnll, "UDP ping-pong over low latency channel on native fake ethernet pair") \
	X(xferudppingllink, "UDP ping-pong over fake ethernet pair in llink mode") \
	X(xferudppingllink_wmm, "UDP ping-pong over fake ethernet pair in llink & wmm mode") \
	X(xferudppingllink_multi, "UDP ping-pong over fake ethernet pair in multi llink mode") \
	X(xferparentchildflow, "flowswitch parent child flows test") \
	X(xferparentchildflown, "flowswitch parent child flows on native fake ethernet interface test") \
	X(xferparentchildflow_offset_400, "flowswitch parent child flows test with demux offset 400") \
	X(xferparentchildflown_offset_400, "flowswitch parent child flows on native fake ethernet interface test with demux offset 400") \
	X(xferrdudpping, "UDP ping-pong between redirect and fake ethernet interface")

/*
 * This is equivalent to the following legacy test command:
 * skywalk_mptests bats
 */
#define X(test, desc, ...)                                                 \
	T_DECL(test, desc, T_META_NAMESPACE("xnu.skywalk_mptests"))        \
	{                                                                  \
	        const char *ignorefail_str = getenv("ignorefail");         \
	        bool ignorefail = false;                                   \
	        if (ignorefail_str) {                                      \
	                T_LOG("ignorefail option present");                \
	                ignorefail = true;                                 \
	        }                                                          \
	        skywalk_mptest_driver_run(&skt_##test, ignorefail);        \
	}
BATS_TESTS;
#undef X
