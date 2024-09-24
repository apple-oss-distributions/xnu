/*
 * Copyright (c) 2016-2024 Apple Inc. All rights reserved.
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
#ifndef _SKYWALK_TEST_COMMON_H_
#define _SKYWALK_TEST_COMMON_H_

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <uuid/uuid.h>
#include <arpa/inet.h>

#include <skywalk/os_skywalk_private.h>
#include <darwintest.h>

#define SKT_LOG(_fmt, ...) do {       \
	int skt_errno = errno;        \
	T_LOG(_fmt, ##__VA_ARGS__);   \
	errno = skt_errno;            \
} while (0)

/* expects a variable "error" */
#define SKTC_ASSERT_ERR(t) do {                                         \
	if (!(t))                                                       \
	        SKT_LOG("%s:%d Unexpected: error %d errno %d: %s",      \
	            __func__, __LINE__, error, errno, strerror(errno)); \
	assert(t);                                                      \
} while (0)

#define SKD(_lvl, _fmt, ...)                          \
	do {                                          \
	        if (sktc_verbose >= (_lvl)) {         \
	                SKT_LOG(_fmt, ##__VA_ARGS__); \
	        }                                     \
	} while (0)

#define SKD0(_fmt, ...) SKD(0, _fmt, ##__VA_ARGS__)
#define SKD1(_fmt, ...) SKD(1, _fmt, ##__VA_ARGS__)
#define SKD2(_fmt, ...) SKD(2, _fmt, ##__VA_ARGS__)
#define SKD3(_fmt, ...) SKD(3, _fmt, ##__VA_ARGS__)

extern int sktc_verbose;
extern nexus_controller_t sktc_nexus_controller;
extern uuid_t sktc_provider_uuid;
extern uuid_t sktc_instance_uuid;
extern uuid_string_t sktc_instance_uuid_string;

void sktc_setup_channel_worker(uuid_t instance_uuid, nexus_port_t channel_port,
    ring_id_t ringid, char *key, size_t keylen, bool echo, bool defunct_ok);
void sktc_cleanup_channel_worker(void);

extern void sktc_generic_upipe_nexus_init(void);
extern void sktc_generic_upipe_echo_init(void);
extern void sktc_generic_upipe_null_init(void);
extern void sktc_generic_upipe_fini(void);
#define SKTC_GENERIC_UPIPE_ARGV { NULL, NULL, NULL, sktc_instance_uuid_string, NULL}

extern void sktc_generic_kpipe_init(void);
extern void sktc_generic_kpipe_fini(void);
#define SKTC_GENERIC_KPIPE_ARGV { NULL, NULL, NULL, sktc_instance_uuid_string, NULL}

extern void sktc_generic_memory_init(void);
extern void sktc_generic_memory_fini(void);

extern channel_slot_t send_bytes(channel_ring_t, uint32_t);
extern int chew_slots(channel_ring_t, uint32_t);
extern void set_watermark(channel_t, bool, channel_threshold_unit_t, uint32_t);

enum timeout_behavior {
	TIMEOUT_FAIL,
	TIMEOUT_EXPECT,
	TIMEOUT_DONT_CARE,
	TIMEOUT_DISABLE
};
extern int wait_on_fd(int, int16_t, channel_t, uint32_t,
    enum timeout_behavior);

struct stage_ctx {
	uint32_t test_stage;
	pthread_cond_t change_cond;
	pthread_mutex_t change_mtx;
};

extern void test_stage_init(struct stage_ctx *, uint32_t);
extern void test_stage_wait(struct stage_ctx *, uint32_t);
extern void test_stage_change(struct stage_ctx *, uint32_t);
extern void test_stage_destroy(struct stage_ctx *);

struct sktc_nexus_attr {
	nexus_name_t    name;
	nexus_type_t    type;
	uint64_t        ntxrings;
	uint64_t        nrxrings;
	uint64_t        ntxslots;
	uint64_t        nrxslots;
	uint64_t        slotsize;
	uint64_t        metasize;
	uint64_t        anonymous;
	uint64_t        userchannel;
	uint64_t        maxfrags;
	uint64_t        rejectonclose;
};

#define SKTC_NEXUS_ATTR_INIT()   \
    {                            \
	    .name = {'\0'},      \
	    .type = -1,          \
	    .ntxrings = -1,      \
	    .nrxrings = -1,      \
	    .ntxslots = -1,      \
	    .nrxslots = -1,      \
	    .slotsize = -1,      \
	    .metasize = -1,      \
	    .anonymous = -1,     \
	    .userchannel = -1,   \
	    .maxfrags = -1,      \
	    .rejectonclose = -1, \
    }

extern void sktc_build_nexus(nexus_controller_t ncd,
    struct sktc_nexus_attr *sktc_attr, uuid_t *providerp, uuid_t *instancep);

extern void sktc_setup_nexus(struct sktc_nexus_attr *);

extern void sktc_cleanup_nexus(void);

extern int sktc_bind_nexus_key(nexus_port_t, const void *, size_t);
extern int sktc_unbind_nexus_key(nexus_port_t);

#define FETH_NAME       "feth"
#define FETH_FORMAT     FETH_NAME "%d"
#define FETH0_NAME      FETH_NAME "0"
#define FETH1_NAME      FETH_NAME "1"

static inline void
sktc_feth_name_for_unit(char * namebuf, size_t namebuf_size, int unit)
{
	snprintf(namebuf, namebuf_size, FETH_FORMAT, unit);
}

extern int sktc_ifnet_feth_create(int unit);
extern int sktc_ifnet_feth_destroy(int unit);

extern void sktc_ifnet_feth0_create(void);
extern void sktc_ifnet_feth0_destroy(void);
extern void sktc_ifnet_feth1_create(void);
extern void sktc_ifnet_feth1_destroy(void);

extern void sktc_ifnet_feth0_1_create(void);
extern void sktc_ifnet_feth0_1_destroy(void);

#define FETH_FLAGS_NATIVE       0x1
#define FETH_FLAGS_TXSTART      0x2
#define FETH_FLAGS_WMM          0x4
#define FETH_FLAGS_MULTI_BUFLET 0x8
#define FETH_FLAGS_NONSHAREDPOOL 0x10
#define FETH_FLAGS_NONSHAREDSPLITPOOLS 0x20
#define FETH_FLAGS_TX_HEADROOM  0x40
#define FETH_FLAGS_USER_ACCESS  0x80
#define FETH_FLAGS_LOW_LATENCY  0x100
#define FETH_FLAGS_NXATTACH     0x200
#define FETH_FLAGS_FCS          0x400
#define FETH_FLAGS_TRAILER      0x800
#define FETH_FLAGS_LLINK        0x1000
#define FETH_FLAGS_MULTI_LLINK  0x2000

extern void sktc_ifnet_feth_pair_create(uint32_t flags);
extern void sktc_ifnet_feth_pair_destroy(void);

#define RD_NAME         "rd"
#define RD_FORMAT       RD_NAME "%d"
#define RD0_NAME        RD_NAME "0"

extern void sktc_ifnet_rd_create(void);
extern void sktc_ifnet_rd_destroy(void);

static inline void
sktc_rd_name_for_unit(char * namebuf, size_t namebuf_size, int unit)
{
	snprintf(namebuf, namebuf_size, RD_FORMAT, unit);
}

#define RD_IF_TYPE_ETHERNET  0x1
#define RD_IF_TYPE_CELLULAR  0x2

extern int sktc_ifnet_add_addr(char *ifname, struct in_addr *addr, struct in_addr *mask, struct in_addr *broadaddr);
extern int sktc_ifnet_add_addr6(char *ifname, struct in6_addr *addr, struct in6_addr *dstaddr, int prefix_len, int flags);
extern int sktc_ifnet_del_addr(char *ifname, struct in_addr *addr);
extern int sktc_ifnet_del_addr6(char *ifname, struct in6_addr *addr);
extern int sktc_ifnet_add_scoped_default_route(char * ifname, struct in_addr ifa);

static inline struct in_addr
sktc_make_in_addr(uint32_t s)
{
	struct in_addr  ip;

	ip.s_addr = htonl(s);
	return ip;
}

#define FETH0_INADDR    0x0a00fa01
#define FETH1_INADDR    0x0a00fb01
#define NOWHERE_INADDR  0x12345678

static inline struct in_addr
sktc_feth0_in_addr(void)
{
	return sktc_make_in_addr(FETH0_INADDR);
}

static inline struct in_addr
sktc_feth1_in_addr(void)
{
	return sktc_make_in_addr(FETH1_INADDR);
}

#define RD0_INADDR    0x0a00fa01

static inline struct in_addr
sktc_rd0_in_addr(void)
{
	_CASSERT(RD0_INADDR == FETH0_INADDR);
	return sktc_make_in_addr(RD0_INADDR);
}

static inline struct in_addr
sktc_nowhere_in_addr(void)
{
	return sktc_make_in_addr(NOWHERE_INADDR);
}

#define FETH0_INET6_ADDR    "ff02::1:ff00:101"
#define FETH1_INET6_ADDR    "ff02::1:ff00:202"

static inline void
sktc_feth0_inet6_addr(struct in6_addr *ip6_addr)
{
	assert(inet_pton(AF_INET6, FETH0_INET6_ADDR, ip6_addr) == 1);
}

static inline void
sktc_feth1_inet6_addr(struct in6_addr *ip6_addr)
{
	assert(inet_pton(AF_INET6, FETH1_INET6_ADDR, ip6_addr) == 1);
}

extern int sktc_get_mac_addr(const char *ifname, uint8_t *addr);
extern bool sktc_get_netif_nexus(const char *ifname, uuid_t netif);
extern bool sktc_get_flowswitch_nexus(const char *ifname, uuid_t fsw);
extern int sktc_ifnet_feth0_set_dequeue_stall(boolean_t enable);
extern int sktc_ifnet_feth1_set_dequeue_stall(boolean_t enable);

typedef enum : uint8_t {
	SKTC_CLASSQ_DEF_C,
	SKTC_CLASSQ_DEF_L4S,
	SKTC_CLASSQ_LL_C,
	SKTC_CLASSQ_LL_L4S,
} sktc_classq_type_t;
extern int sktc_set_classq_update_interval(uint64_t ns, sktc_classq_type_t type);
extern int sktc_reset_classq_update_interval(sktc_classq_type_t type);
extern int sktc_set_classq_target_qdelay(uint64_t ns, sktc_classq_type_t type);
extern int sktc_reset_classq_target_qdelay(sktc_classq_type_t type);
extern int sktc_set_classq_update_intervals(uint64_t ns);
extern int sktc_reset_classq_update_intervals(void);
extern int sktc_set_classq_target_qdelays(uint64_t ns);
extern int sktc_reset_classq_target_qdelays(void);

extern void sktc_set_tcp_msl(int);
extern void sktc_restore_tcp_msl(void);
extern void sktc_enable_ip_reass();
extern void sktc_restore_ip_reass();
extern bool sktc_is_ip_reass_enabled();
extern bool sktc_is_netagent_enabled(void);
extern uint64_t sktc_get_channel_attr(const channel_t chd,
    channel_attr_type_t type);
extern void sktc_config_fsw_rx_agg_tcp(uint32_t);
extern void sktc_restore_fsw_rx_agg_tcp(void);
extern void sktc_enable_channel_buflet_alloc(void);
extern void sktc_restore_channel_buflet_alloc(void);
extern void skt_process_if_adv(nexus_port_t port, channel_t chan);

/*
 * Process a channel event:
 * - Validate that the event data len matches the event type.
 * - Validate that a matching handler is passed, and invoke it.
 * - If no matching handler is defined, the validation fails.
 */
typedef void (^transmit_status_event_handler_t)(
	const os_channel_event_packet_transmit_status_t *event_data);
typedef void (^transmit_expired_event_handler_t)(
	const os_channel_event_packet_transmit_expired_t *event_data);
typedef void (^wildcard_event_handler_t)(
	os_channel_event_type_t event_type,
	const uint8_t *event_data,
	size_t event_dlen);

extern void skt_process_channel_event(
	channel_t chan, uint8_t payload_type, uint32_t stream_id,
	transmit_status_event_handler_t transmit_status_handler,
	transmit_expired_event_handler_t transmit_expired_handler,
	wildcard_event_handler_t wildcard_handler);
extern int skt_add_arp_entry(struct in_addr host, struct ether_addr *eaddr);
void skt_aqstatpr(const char *interface);

struct protox {
	void    (*pr_cblocks)(uint32_t, char *, int);
	/* control blocks printing routine */
	void    (*pr_stats)(uint32_t, char *, int);
	/* statistics printing routine */
	void    (*pr_istats)(char *);   /* per/if statistics printing routine */
	char    *pr_name;               /* well-known name */
	int     pr_protocol;
};
extern struct protox protox[];
void skt_printproto(register struct protox *tp, char *name);

const char *BOLD;
const char *BOLD_RED;
const char *BOLD_GREEN;
const char *BOLD_YELLOW;
const char *BOLD_BLUE;
const char *BOLD_MAGENTA;
const char *BOLD_CYAN;
const char *BOLD_WHITE;
const char *NORMAL;

#endif /* _SKYWALK_TEST_COMMON_H_ */
