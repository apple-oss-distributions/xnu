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
#ifndef _SKYWALK_TEST_DRIVER_H_
#define _SKYWALK_TEST_DRIVER_H_

#include <stdlib.h>
#include <stdbool.h>

#include "skywalk_test_common.h"
#include "skywalk_test_utils.h"

#define SKT_MAX_ARGV 8

struct skywalk_test {
	const char *skt_testname;
	const char *skt_testdesc;
	uint64_t skt_required_features;
	int (*skt_main)(int argc, char **);
	char *skt_argv[SKT_MAX_ARGV];
	void (*skt_init)(void);
	void (*skt_fini)(void);
	uint64_t skt_expected_exception_code;
	uint64_t skt_expected_exception_code_ignore;
	char skt_argv2[11]; // dynamically initialized default argv2
};

extern int skywalk_test_driver_run(struct skywalk_test *, int, char **,
    uint32_t, bool, bool, int);

struct skywalk_mptest {
	const char *skt_testname;
	const char *skt_testdesc;
	uint64_t skt_required_features;
	int skt_nchildren;
	int (*skt_main)(int argc, char *argv[]);
	char *skt_argv[SKT_MAX_ARGV];
	void (*skt_init)(void);
	void (*skt_fini)(void);
	char skt_argv2[11]; // dynamically initialized default argv2
};

struct skywalk_mptest_check {
	const char *skt_testname;
	bool (*skt_supported)(void);
};

#define MPTEST_SEQ_FILENO 3
extern bool skywalk_in_driver; // true only if in skywalk test driver process

extern int skywalk_mptest_driver_run(struct skywalk_mptest *, bool);

extern struct skywalk_test skt_noop;
extern struct skywalk_test skt_crash;
extern struct skywalk_test skt_assert;
extern struct skywalk_test skt_features;
extern struct skywalk_test skt_oneslotus;
extern struct skywalk_test skt_oneslotks;
extern struct skywalk_test skt_oneslotup;
extern struct skywalk_test skt_oneslotkp;
extern struct skywalk_test skt_oneslotuk;
extern struct skywalk_test skt_oneslotuk_defunct;
extern struct skywalk_test skt_oneslotkk;
extern struct skywalk_test skt_shutdownus;
extern struct skywalk_test skt_shutdownks;
extern struct skywalk_test skt_shutdownup;
extern struct skywalk_test skt_shutdownkp;
extern struct skywalk_test skt_shutdownuk;
extern struct skywalk_test skt_shutdownkk;
extern struct skywalk_test skt_shutdown2us;
extern struct skywalk_test skt_shutdown2ks;
extern struct skywalk_test skt_shutdown2up;
extern struct skywalk_test skt_shutdown2kp;
extern struct skywalk_test skt_shutdown2uk;
extern struct skywalk_test skt_shutdown2kk;
extern struct skywalk_test skt_nslotsus;
extern struct skywalk_test skt_nslotsks;
extern struct skywalk_test skt_nslotsup;
extern struct skywalk_test skt_nslotskp;
extern struct skywalk_test skt_nslotsuk;
extern struct skywalk_test skt_nslotskk;
extern struct skywalk_test skt_mslotsus;
extern struct skywalk_test skt_mslotsks;
extern struct skywalk_test skt_mslotsup;
extern struct skywalk_test skt_mslotskp;
extern struct skywalk_test skt_mslotsuk;
extern struct skywalk_test skt_mslotskk;
extern struct skywalk_test skt_mmslotsus;
extern struct skywalk_test skt_mmslotsks;
extern struct skywalk_test skt_mmslotsup;
extern struct skywalk_test skt_mmslotskp;
extern struct skywalk_test skt_mmslotsuk;
extern struct skywalk_test skt_mmslotskk;
extern struct skywalk_test skt_closecfd;
extern struct skywalk_test skt_writecfd;
extern struct skywalk_test skt_readcfd;
extern struct skywalk_test skt_closenfd;
extern struct skywalk_test skt_writenfd;
extern struct skywalk_test skt_readnfd;
extern struct skywalk_test skt_writeif;
extern struct skywalk_test skt_writering;
extern struct skywalk_test skt_readsmap;
extern struct skywalk_test skt_writesmap;
extern struct skywalk_test skt_badringtl;
extern struct skywalk_test skt_badringtp;
extern struct skywalk_test skt_badringtk;
extern struct skywalk_test skt_badringts;
extern struct skywalk_test skt_badringrl;
extern struct skywalk_test skt_badringrp;
extern struct skywalk_test skt_badringrk;
extern struct skywalk_test skt_badringrs;
extern struct skywalk_test skt_kqueue_basic;
extern struct skywalk_test skt_kqueue_lowat_chan_slots;
extern struct skywalk_test skt_kqueue_lowat_chan_bytes;
extern struct skywalk_test skt_kqueue_lowat_note_slots;
extern struct skywalk_test skt_kqueue_lowat_note_bytes;
extern struct skywalk_test skt_change_len;
extern struct skywalk_test skt_big_len;
extern struct skywalk_test skt_internalizemetdata;
extern struct skywalk_test skt_ringidtx;
extern struct skywalk_test skt_ringidrx;
extern struct skywalk_test skt_closekqk;
extern struct skywalk_test skt_debug_verify_u;
extern struct skywalk_test skt_debug_verify_k;
extern struct skywalk_test skt_utun27302538a;
extern struct skywalk_test skt_utun27302538b;
extern struct skywalk_test skt_utun27302538c;
extern struct skywalk_test skt_utun27302538d;
extern struct skywalk_test skt_utun27646755;
extern struct skywalk_test skt_utun27646755slow;
extern struct skywalk_test skt_utunleak;
extern struct skywalk_test skt_utunloopn4u1;
extern struct skywalk_test skt_utunloopn4u2;
extern struct skywalk_test skt_utunloopn4t1;
extern struct skywalk_test skt_utunloopn4t2;
extern struct skywalk_test skt_utunloopy4u1;
extern struct skywalk_test skt_utunloopy4u2;
extern struct skywalk_test skt_utunloopy4t1;
extern struct skywalk_test skt_utunloopy4t2;
extern struct skywalk_test skt_utunloopn1000;
extern struct skywalk_test skt_utunloopy1000;
extern struct skywalk_test skt_ipsecloopy4u1;
extern struct skywalk_test skt_ipsecloopy4u2;
extern struct skywalk_test skt_ipsecloopy4t1;
extern struct skywalk_test skt_ipsecloopy4t2;
extern struct skywalk_test skt_ipsecloopy1000;
extern struct skywalk_test skt_bindupipeanon;
extern struct skywalk_test skt_bindupipekey;
extern struct skywalk_test skt_bindfswanon;
extern struct skywalk_test skt_bindfswkey;
extern struct skywalk_test skt_bindnetifkey;
extern struct skywalk_test skt_flowswitch_ns_reserve;
extern struct skywalk_test skt_flowswitch_ns_reserve2;
extern struct skywalk_test skt_netifcompata;
extern struct skywalk_test skt_netifcompatb;
extern struct skywalk_test skt_netifcompatc;
extern struct skywalk_test skt_netiffsw;
extern struct skywalk_test skt_netifdelete;
extern struct skywalk_test skt_fswloopfsw;
extern struct skywalk_test skt_fswloop2ff;
extern struct skywalk_test skt_fswloop2nff;
extern struct skywalk_test skt_teardown;
extern struct skywalk_test skt_teardownb;
extern struct skywalk_test skt_teardownr;
extern struct skywalk_test skt_teardownz;
extern struct skywalk_test skt_fsw29301703a;
extern struct skywalk_test skt_fsw29301703b;
extern struct skywalk_test skt_fsw29301703c;
extern struct skywalk_test skt_fswbindany;
extern struct skywalk_test skt_fswbind0;
extern struct skywalk_test skt_fswbind1;
extern struct skywalk_test skt_fswbind512;
extern struct skywalk_test skt_fswbind2;
extern struct skywalk_test skt_fswbind5;
extern struct skywalk_test skt_fswbind25;
extern struct skywalk_test skt_mf10x10;
extern struct skywalk_test skt_mf10x100;
extern struct skywalk_test skt_mf100x10;
extern struct skywalk_test skt_mf100x100;
extern struct skywalk_test skt_mf1xall;
extern struct skywalk_test skt_mf1xallslow;
extern struct skywalk_test skt_fullupipe;
extern struct skywalk_test skt_upipepeerclosure;
extern struct skywalk_test skt_pllupipe;
extern struct skywalk_test skt_pllutxk;
extern struct skywalk_test skt_pllutxs;
extern struct skywalk_test skt_pllutxp;
extern struct skywalk_test skt_pllurxk;
extern struct skywalk_test skt_pllurxs;
extern struct skywalk_test skt_pllurxp;
extern struct skywalk_test skt_listener;
extern struct skywalk_test skt_listener_stress;
extern struct skywalk_test skt_listener_reuse;
extern struct skywalk_test skt_listen_stress;
extern struct skywalk_test skt_copy_cksum_single;
extern struct skywalk_test skt_copy_cksum_multi;
extern struct skywalk_test skt_reass_default_setting;
extern struct skywalk_test skt_reass;
extern struct skywalk_test skt_reass_timeout;
extern struct skywalk_test skt_reass_bad_fraglen;
extern struct skywalk_test skt_reass_atomic;
extern struct skywalk_test skt_reass_fuzz_queue_limit;
extern struct skywalk_test skt_verifynxadv;
extern struct skywalk_test skt_cksum;
extern struct skywalk_test skt_memory;
extern struct skywalk_test skt_flow_req;
extern struct skywalk_test skt_flow_req_ll;
extern struct skywalk_test skt_flow_config;
extern struct skywalk_test skt_flowlookup;
extern struct skywalk_test skt_libcuckoo;
extern struct skywalk_test skt_restricted_port;
extern struct skywalk_test skt_steering;


extern struct skywalk_mptest skt_mp100noop;
extern struct skywalk_mptest skt_mc10x10;
extern struct skywalk_mptest skt_mc10x100;
extern struct skywalk_mptest skt_mc100x10;
extern struct skywalk_mptest skt_mc100x100;
extern struct skywalk_mptest skt_mpprotons;
extern struct skywalk_mptest skt_xferudp;
extern struct skywalk_mptest skt_xferudpn;
extern struct skywalk_mptest skt_xferudpnsp;
extern struct skywalk_mptest skt_xferudpfcs;
extern struct skywalk_mptest skt_xferudptrailer;
extern struct skywalk_mptest skt_xferudpnfcs;
extern struct skywalk_mptest skt_xferudpntrailer;
extern struct skywalk_mptest skt_xferudplong;
extern struct skywalk_mptest skt_xferudplongn;
extern struct skywalk_mptest skt_xferudpoverwhelm;
extern struct skywalk_mptest skt_xferudpoverwhelmn;
extern struct skywalk_mptest skt_xferudpoverwhelmnsp;
extern struct skywalk_mptest skt_xferudpoverwhelmlong;
extern struct skywalk_mptest skt_xferudpoverwhelmlongn;
extern struct skywalk_mptest skt_xferudpping;
extern struct skywalk_mptest skt_xferudppingn;
extern struct skywalk_mptest skt_xferudpping_aqm;
extern struct skywalk_mptest skt_xferudppingn_aqm;
extern struct skywalk_mptest skt_xferudpping1;
extern struct skywalk_mptest skt_xferudpping1n;
extern struct skywalk_mptest skt_xferudppinglong;
extern struct skywalk_mptest skt_xferudppinglongn;
extern struct skywalk_mptest skt_xferudpping1wrong;
extern struct skywalk_mptest skt_xfertcpsynflood;
extern struct skywalk_mptest skt_xfertcprstflood;
extern struct skywalk_mptest skt_xferudpwitherrors;
extern struct skywalk_mptest skt_xferudpwitherrorscompat;
extern struct skywalk_mptest skt_xfertcpportzero;
extern struct skywalk_mptest skt_xferudpportzero;
extern struct skywalk_mptest skt_xfersetuponly;
extern struct skywalk_mptest skt_xfersetuponlyn;
extern struct skywalk_mptest skt_xferudppingn_wmm;
extern struct skywalk_mptest skt_xferflowmatch;
extern struct skywalk_mptest skt_xferflowcleanup;
extern struct skywalk_mptest skt_xferudppingn_mb;
extern struct skywalk_mptest skt_xferfastlane;
extern struct skywalk_mptest skt_xferfastlanen;
extern struct skywalk_mptest skt_xferrfc4594;
extern struct skywalk_mptest skt_xferrfc4594n;
extern struct skywalk_mptest skt_xfercsumoffload;
extern struct skywalk_mptest skt_xfercsumoffloadn;
extern struct skywalk_mptest skt_xferudpfrags;
extern struct skywalk_mptest skt_xferudpbadfrags;
extern struct skywalk_mptest skt_xferlistenertcprst;
extern struct skywalk_mptest skt_netifdirecttxrx;
extern struct skywalk_mptest skt_netifdirecttxrxsp;
extern struct skywalk_mptest skt_netifdirecttxrxcopymode;
extern struct skywalk_mptest skt_netifdirectifadvenable;
extern struct skywalk_mptest skt_netifdirectifadvdisable;
extern struct skywalk_mptest skt_netifdirectchanevents;
extern struct skywalk_mptest skt_netifdirectexpiryevents;
extern struct skywalk_mptest skt_filternative;
extern struct skywalk_mptest skt_filtercompat;
extern struct skywalk_mptest_check skt_filternative_check;
extern struct skywalk_mptest_check skt_filtercompat_check;
extern struct skywalk_mptest skt_xferudpifadvenable;
extern struct skywalk_mptest skt_xferudpifadvdisable;
extern struct skywalk_mptest skt_xferudppingnll;
extern struct skywalk_mptest skt_xferudppingllink;
extern struct skywalk_mptest skt_xferudppingllink_wmm;
extern struct skywalk_mptest skt_xferudppingllink_multi;
extern struct skywalk_mptest skt_xferudpchanevents;
extern struct skywalk_mptest skt_xferudpchaneventsasync;
extern struct skywalk_mptest skt_xferparentchildflow;
extern struct skywalk_mptest skt_xferparentchildflown;
extern struct skywalk_mptest skt_xferparentchildflow_offset_400;
extern struct skywalk_mptest skt_xferparentchildflown_offset_400;
extern struct skywalk_mptest skt_xferrdudpping;

extern struct skywalk_mptest_check skt_filternative_check;
extern struct skywalk_mptest_check skt_filtercompat_check;

#endif /* _SKYWALK_TEST_DRIVER_H_ */
