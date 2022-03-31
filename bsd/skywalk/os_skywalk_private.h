/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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
#ifndef _SKYWALK_OS_SKYWALK_PRIVATE_H
#define _SKYWALK_OS_SKYWALK_PRIVATE_H

#if defined(PRIVATE) || defined(XNU_KERNEL_PRIVATE)
/*
 * This file contains private interfaces for Skywalk, and should not
 * be included by code external to xnu kernel or libsystem_kernel.
 * The only exception to this is skywalk_cmds for the internal tools.
 */

/* branch prediction helpers */
#include <sys/cdefs.h>
#define SK_ALIGN64_CASSERT(type, field) \
	_CASSERT((__builtin_offsetof(type, field) % sizeof (uint64_t)) == 0)

#if !defined(KERNEL) || defined(BSD_KERNEL_PRIVATE)
enum {
	SK_FEATURE_SKYWALK = 1ULL << 0,
	SK_FEATURE_DEVELOPMENT = 1ULL << 1,
	SK_FEATURE_DEBUG = 1ULL << 2,
	SK_FEATURE_NEXUS_FLOWSWITCH = 1ULL << 3,
	SK_FEATURE_NEXUS_MONITOR = 1ULL << 4,
	SK_FEATURE_NEXUS_NETIF = 1ULL << 5,
	SK_FEATURE_NEXUS_USER_PIPE = 1ULL << 6,
	SK_FEATURE_NEXUS_KERNEL_PIPE = 1ULL << 7,
	SK_FEATURE_NEXUS_KERNEL_PIPE_LOOPBACK = 1ULL << 8,
	SK_FEATURE_DEV_OR_DEBUG = 1ULL << 9,
	SK_FEATURE_NETNS = 1ULL << 10,
	SK_FEATURE_PROTONS = 1ULL << 11,
};
#endif /* !KERNEL || BSD_KERNEL_PRIVATE */

/* valid flags for if_attach_nx */
#define IF_ATTACH_NX_NETIF_COMPAT               0x01    /* create compat netif */
#define IF_ATTACH_NX_FLOWSWITCH                 0x02    /* enable flowswitch */
#define IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT     0x04    /* enable fsw TCP/UDP netagent */
#define IF_ATTACH_NX_NETIF_NETAGENT             0x08    /* enable netif netagent */
#define IF_ATTACH_NX_NETIF_ALL                  0x10    /* don't restrict netif */
#define IF_ATTACH_NX_FSW_IP_NETAGENT            0x20    /* enable fsw IP netagent */

/*
 * Enabling Skywalk channel (user) networking stack fundamentally requires
 * the presence of netif nexus attached to the interface.  Native Skywalk
 * drivers will come with a netif nexus; non-native drivers will require us
 * to create a netif compat nexus, set through IF_ATTACH_NX_NETIF_COMPAT.
 *
 * The flowswitch nexus creation depends on the presence of netif nexus on
 * the interface.  Plumbing the flowswitch atop netif is required to connect
 * the interface to the host (kernel) networking stack; this is the default
 * behavior unless IF_ATTACH_NX_FLOWSWITCH is not set.
 *
 * To further allow for channel (user) networking stack, the netagent gets
 * enabled on the flowswitch by default, unless opted out by clearing the
 * IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT flag. Note that
 * IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT cannot be changed after boot, and so has
 * to be set by the if_attach_nx bootarg.
 */
#define SKYWALK_NETWORKING_ENABLED                              \
	(IF_ATTACH_NX_NETIF_COMPAT | IF_ATTACH_NX_FLOWSWITCH |  \
	IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT)

/*
 * To partially enable Skywalk to only let the host (kernel) stack to work,
 * we set both IF_ATTACH_NX_NETIF_COMPAT and IF_ATTACH_NX_FLOWSWITCH flags,
 * leaving IF_ATTACH_NX_FSW_*_NETAGENT unset. This enables netif and
 * flowswitch flowswitch nexus on all eligible interfaces, except that channel
 * (user) networking stack will be disabled.
 */
#define SKYWALK_NETWORKING_BSD_ONLY     \
	(IF_ATTACH_NX_NETIF_COMPAT | IF_ATTACH_NX_FLOWSWITCH)

/*
 * macOS default configuration for enabling support for interpose filters,
 * custom IP, custom ether type providers and user networking stack.
 */
#define SKYWALK_NETWORKING_MAC_OS     \
	(SKYWALK_NETWORKING_BSD_ONLY | IF_ATTACH_NX_FSW_IP_NETAGENT | \
	IF_ATTACH_NX_NETIF_NETAGENT | IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT)

/*
 * Disabling Skywalk networking is done by removing IF_ATTACH_NX_NETIF_COMPAT
 * and IF_ATTACH_NX_FSW_*_NETAGENT flags, and leaving IF_ATTACH_NX_FLOWSWITCH
 * set. This disables the compat netif instances and netagent, while still
 * allowing flowswitch nexus creation for native Skywalk drivers, since
 * otherwise they cease to function due to missing interaction with the host
 * (kernel) stack.
 */
#define SKYWALK_NETWORKING_DISABLED     IF_ATTACH_NX_FLOWSWITCH

#if !XNU_TARGET_OS_OSX
#ifdef __LP64__
#define IF_ATTACH_NX_DEFAULT    SKYWALK_NETWORKING_ENABLED
#else /* !__LP64__ */
#define IF_ATTACH_NX_DEFAULT    SKYWALK_NETWORKING_DISABLED
#endif /* !__LP64__ */
#else /* XNU_TARGET_OS_OSX */
#define IF_ATTACH_NX_DEFAULT    SKYWALK_NETWORKING_MAC_OS
#endif /* XNU_TARGET_OS_OSX */

#define SK_VERBOSE_SYSCTL       "kern.skywalk.verbose"
/*
 * Verbose flags.
 *
 * When adding new ones, consider the existing scheme based on the areas;
 * try to "fill in the holes" first before extending the range.
 */
#define SK_VERB_FLAGS_TABLE(X)  \
	X(SK_VERB_DEFAULT,		0)      /* 0x0000000000000001 */ \
	X(SK_VERB_DUMP,			1)      /* 0x0000000000000002 */ \
	X(SK_VERB_LOCKS,		2)      /* 0x0000000000000004 */ \
	X(SK_VERB_REFCNT,		3)      /* 0x0000000000000008 */ \
	X(SK_VERB_MEM,			4)      /* 0x0000000000000010 */ \
	X(SK_VERB_MEM_ARENA,		5)      /* 0x0000000000000020 */ \
	X(SK_VERB_MEM_CACHE,		6)      /* 0x0000000000000040 */ \
	X(SK_VERB_MEM_REGION,		7)      /* 0x0000000000000080 */ \
	X(SK_VERB_EVENTS,		8)      /* 0x0000000000000100 */ \
	X(SK_VERB_SYNC,			9)      /* 0x0000000000000200 */ \
	X(SK_VERB_NOTIFY,		10)     /* 0x0000000000000400 */ \
	X(SK_VERB_INTR,			11)     /* 0x0000000000000800 */ \
	X(SK_VERB_MONITOR,		12)     /* 0x0000000000001000 */ \
	X(SK_VERB_DEV,			13)     /* 0x0000000000002000 */ \
	X(SK_VERB_HOST,			14)     /* 0x0000000000004000 */ \
	X(SK_VERB_USER,			15)     /* 0x0000000000008000 */ \
	X(SK_VERB_RX,			16)     /* 0x0000000000010000 */ \
	X(SK_VERB_TX,			17)     /* 0x0000000000020000 */ \
	X(SK_VERB_LOOKUP,		18)     /* 0x0000000000040000 */ \
	X(SK_VERB_RING,			19)     /* 0x0000000000080000 */ \
	X(SK_VERB_NETIF,		20)     /* 0x0000000000100000 */ \
	X(SK_VERB_NETIF_MIT,		21)     /* 0x0000000000200000 */ \
	X(SK_VERB_IOSK,			22)     /* 0x0000000000400000 */ \
	X(SK_VERB_CHANNEL,		23)     /* 0x0000000000800000 */ \
	X(SK_VERB_AQM,			25)     /* 0x0000000002000000 */ \
	X(SK_VERB_FSW,			24)     /* 0x0000000001000000 */ \
	X(SK_VERB_FSW_DP,		26)     /* 0x0000000004000000 */ \
	X(SK_VERB_LLINK,		27)     /* 0x0000000008000000 */ \
	X(SK_VERB_FLOW,			28)     /* 0x0000000010000000 */ \
	X(SK_VERB_FLOW_CLASSIFY,	29)     /* 0x0000000020000000 */ \
	X(SK_VERB_FLOW_TRACK,		30)     /* 0x0000000040000000 */ \
	X(SK_VERB_FLOW_ADVISORY,	31)     /* 0x0000000080000000 */ \
	X(SK_VERB_FLOW_ROUTE,		32)     /* 0x0000000100000000 */ \
	X(__SK_VERB_33__,		33)     /* 0x0000000200000000 */ \
	X(__SK_VERB_34__,		34)     /* 0x0000000400000000 */ \
	X(__SK_VERF_35__,		35)     /* 0x0000000800000000 */ \
	X(SK_VERB_USER_PIPE,		36)     /* 0x0000001000000000 */ \
	X(SK_VERB_NA,			37)     /* 0x0000002000000000 */ \
	X(SK_VERB_KERNEL_PIPE,		38)     /* 0x0000004000000000 */ \
	X(SK_VERB_NS_PROTO,		39)     /* 0x0000008000000000 */ \
	X(SK_VERB_NS_TCP,		40)     /* 0x0000010000000000 */ \
	X(SK_VERB_NS_UDP,		41)     /* 0x0000020000000000 */ \
	X(SK_VERB_NS_IPV4,		42)     /* 0x0000040000000000 */ \
	X(SK_VERB_NS_IPV6,		43)     /* 0x0000080000000000 */ \
	X(SK_VERB_COPY,			44)     /* 0x0000100000000000 */ \
	X(SK_VERB_COPY_MBUF,		45)     /* 0x0000200000000000 */ \
	X(SK_VERB_MOVE,			46)     /* 0x0000400000000000 */ \
	X(SK_VERB_MOVE_MBUF,		47)     /* 0x0000800000000000 */ \
	X(SK_VERB_IP_FRAG,		48)     /* 0x0001000000000000 */ \
	X(SK_VERB_ERROR_INJECT,		49)     /* 0x0002000000000000 */ \
	X(SK_VERB_QOS,			50)     /* 0x0004000000000000 */ \
	X(SK_VERB_NXPORT,		51)     /* 0x0008000000000000 */ \
	X(SK_VERB_FILTER,		52)     /* 0x0010000000000000 */ \
	X(SK_VERB_VP,			53)     /* 0x0020000000000000 */ \
	X(SK_VERB_NETIF_POLL,		54)     /* 0x0040000000000000 */ \
	X(SK_VERB_DROP,			55)     /* 0x0080000000000000 */ \
	X(__SK_VERB_56__,		56)     /* 0x0100000000000000 */ \
	X(__SK_VERB_57__,		57)     /* 0x0200000000000000 */ \
	X(__SK_VERB_58__,		58)     /* 0x0400000000000000 */ \
	X(__SK_VERB_59__,		59)     /* 0x0800000000000000 */ \
	X(__SK_VERB_60__,		60)     /* 0x1000000000000000 */ \
	X(__SK_VERB_61__,		61)     /* 0x2000000000000000 */ \
	X(SK_VERB_PRIV,			62)     /* 0x4000000000000000 */ \
	X(SK_VERB_ERROR,		63)     /* 0x8000000000000000 */

#define EXPAND_TO_STRING(name, bitshift) #name,
#define EXPAND_TO_ENUMERATION(name, bitshift) name = (1ULL << bitshift),

static const char *sk_verb_flags_string[] = {
	SK_VERB_FLAGS_TABLE(EXPAND_TO_STRING)
};

enum SK_VERB_FLAGS {
	SK_VERB_FLAGS_TABLE(EXPAND_TO_ENUMERATION)
};

#define SK_VERB_FLAGS_STRINGS_MAX       \
	(sizeof (sk_verb_flags_string) / sizeof (sk_verb_flags_string[0]))

#undef  EXPAND_TO_STRING
#undef  EXPAND_TO_ENUMERATION

#ifdef KERNEL
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <mach/vm_types.h>
#include <mach/vm_param.h>
#include <kern/cpu_number.h>
#include <pexpert/pexpert.h>

#if (DEVELOPMENT || DEBUG)
#define SK_KVA(p)       ((uint64_t)(p))
#define SK_LOG          1
#else
#define SK_KVA(p)       ((uint64_t)VM_KERNEL_ADDRPERM(p))
#define SK_LOG          0
#endif /* !DEVELOPMENT && !DEBUG */

#if SK_LOG
#define SK_LOG_VAR(x) x
#else
#define SK_LOG_VAR(x)
#endif

#define SK_INLINE_ATTRIBUTE     __attribute__((always_inline))
#define SK_NO_INLINE_ATTRIBUTE  __attribute__((noinline))
#define SK_LOG_ATTRIBUTE        __attribute__((noinline, cold, not_tail_called))

#if SK_LOG
/*
 * Because the compiler doesn't know about the %b format specifier,
 * most warnings for _SK_D are disabled by pragma.
 *
 * XXX adi@apple.com: This means the compiler will not warn us about
 * invalid parameters passed to kprintf(), so make sure to scrutinize
 * any changes made to code using any logging macros defined below.
 */

extern uint64_t sk_verbose;
#define _SK_D(_flag, _fmt, ...) do {                                    \
	if (__improbable(((_flag) && (sk_verbose & (_flag)) == (_flag)) || \
	    (_flag) == SK_VERB_ERROR)) {                                \
	        _Pragma("clang diagnostic push")                        \
	        _Pragma("clang diagnostic ignored \"-Wformat-invalid-specifier\"") \
	        _Pragma("clang diagnostic ignored \"-Wformat-extra-args\"") \
	        _Pragma("clang diagnostic ignored \"-Wformat\"") \
	        kprintf("SK[%u]: %-30s " _fmt "\n",                     \
	            cpu_number(), __FUNCTION__, ##__VA_ARGS__);         \
	        _Pragma("clang diagnostic pop")                         \
	}                                                               \
} while (0)

#define SK_DF(_flag, _fmt, ...) _SK_D((uint64_t)_flag, _fmt, ##__VA_ARGS__)
#define SK_D(_fmt, ...)         SK_DF(SK_VERB_DEFAULT, _fmt, ##__VA_ARGS__)
#define SK_ERR(_fmt, ...)       SK_DF(SK_VERB_ERROR, _fmt, ##__VA_ARGS__)
#define SK_DSC(_p, _fmt, ...)   SK_ERR("%s(%d): " _fmt,                 \
	sk_proc_name_address(_p), sk_proc_pid(_p), ##__VA_ARGS__)

/* rate limited, lps indicates how many per second */
#define _SK_RD(_flag, _lps, _fmt, ...) do {                             \
	static int __t0, __now, __cnt;                                  \
	__now = (int)_net_uptime;                                       \
	if (__t0 != __now) {                                            \
	        __t0 = __now;                                           \
	        __cnt = 0;                                              \
	}                                                               \
	if (__cnt++ < (_lps))                                           \
	        SK_DF(_flag, _fmt, ##__VA_ARGS__);                      \
} while (0)

#define SK_RDF(_flag, _lps, _fmt, ...)  \
	_SK_RD(_flag, _lps, _fmt, ##__VA_ARGS__)
#define SK_RD(_lps, _fmt, ...)          \
	SK_RDF(SK_VERB_DEFAULT, _lps, _fmt, ##__VA_ARGS__)
#define SK_RDERR(_lps, _fmt, ...)       \
	SK_RDF(SK_VERB_ERROR, _lps, _fmt, ##__VA_ARGS__)
#else /* !SK_LOG */
#define SK_DF(_flag, _fmt, ...)         do { ((void)0); } while (0)
#define SK_D(_fmt, ...)                 do { ((void)0); } while (0)
#define SK_ERR(_fmt, ...)               do { ((void)0); } while (0)
#define SK_DSC(_p, _fmt, ...)           do { ((void)0); } while (0)
#define SK_RDF(_flag, _lps, _fmt, ...)  do { ((void)0); } while (0)
#define SK_RD(_lps, _fmt, ...)          do { ((void)0); } while (0)
#define SK_RDERR(_lps, _fmt, ...)       do { ((void)0); } while (0)
#endif /* ! SK_LOG */

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/lib/cuckoo_hashtable.h>
#include <skywalk/mem/skmem_var.h>
#include <skywalk/channel/os_channel_event.h>
#include <skywalk/channel/channel_var.h>
#include <skywalk/nexus/nexus_var.h>
#include <skywalk/packet/pbufpool_var.h>
#include <skywalk/packet/packet_var.h>
#endif /* BSD_KERNEL_PRIVATE */
#endif /* KERNEL */
#if !defined(KERNEL) || defined(BSD_KERNEL_PRIVATE)
#include <skywalk/skywalk_common.h>
#include <skywalk/os_nexus_private.h>
#include <skywalk/os_channel_private.h>
#include <skywalk/os_packet_private.h>
#include <skywalk/os_stats_private.h>
#endif /* !KERNEL || BSD_KERNEL_PRIVATE */
#endif /* PRIVATE || XNU_KERNEL_PRIVATE */
#endif /* _SKYWALK_OS_SKYWALK_PRIVATE_H */
