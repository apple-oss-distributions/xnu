/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the University of
 *    California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *    From: @(#)if.h    8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if_var.h,v 1.18.2.7 2001/07/24 19:10:18 brooks Exp $
 */

#ifndef _NET_IF_VAR_STATUS_H_
#define _NET_IF_VAR_STATUS_H_

#include <machine/types.h>
#include <stdint.h>

#pragma pack(4)

/*
 * Interface link status report -- includes statistics related to
 * the link layer technology sent by the driver. The driver will monitor
 * these statistics over an interval (3-4 secs) and will generate a report
 * to the network stack. This will give first-hand information about the
 * status of the first hop of the network path. The version and
 * length values should be correct for the data to be processed correctly.
 * The definitions are different for different kind of interfaces like
 * Wifi, Cellular etc,.
 */
#define IF_CELLULAR_STATUS_REPORT_VERSION_1     1
#define IF_WIFI_STATUS_REPORT_VERSION_1         1
#define IF_CELLULAR_STATUS_REPORT_CURRENT_VERSION       \
	                                IF_CELLULAR_STATUS_REPORT_VERSION_1
#define IF_WIFI_STATUS_REPORT_CURRENT_VERSION   IF_WIFI_STATUS_REPORT_VERSION_1
/*
 * For cellular interface --
 * There is no way to share common headers between the Baseband and
 * the kernel. Any changes to this structure will need to be communicated
 * to the Baseband team. It is better to use reserved space instead of
 * changing the size or existing fields in the structure.
 */
struct if_cellular_status_v1 {
	u_int32_t valid_bitmask;     /* indicates which fields are valid */
#define IF_CELL_LINK_QUALITY_METRIC_VALID       0x1
#define IF_CELL_UL_EFFECTIVE_BANDWIDTH_VALID    0x2
#define IF_CELL_UL_MAX_BANDWIDTH_VALID          0x4
#define IF_CELL_UL_MIN_LATENCY_VALID            0x8
#define IF_CELL_UL_EFFECTIVE_LATENCY_VALID      0x10
#define IF_CELL_UL_MAX_LATENCY_VALID            0x20
#define IF_CELL_UL_RETXT_LEVEL_VALID            0x40
#define IF_CELL_UL_BYTES_LOST_VALID             0x80
#define IF_CELL_UL_MIN_QUEUE_SIZE_VALID         0x100
#define IF_CELL_UL_AVG_QUEUE_SIZE_VALID         0x200
#define IF_CELL_UL_MAX_QUEUE_SIZE_VALID         0x400
#define IF_CELL_DL_EFFECTIVE_BANDWIDTH_VALID    0x800
#define IF_CELL_DL_MAX_BANDWIDTH_VALID          0x1000
#define IF_CELL_CONFIG_INACTIVITY_TIME_VALID    0x2000
#define IF_CELL_CONFIG_BACKOFF_TIME_VALID       0x4000
#define IF_CELL_UL_MSS_RECOMMENDED_VALID        0x8000

	u_int32_t link_quality_metric;
	u_int32_t ul_effective_bandwidth; /* Measured uplink bandwidth based on current activity (bps) */
	u_int32_t ul_max_bandwidth; /* Maximum supported uplink bandwidth (bps) */
	u_int32_t ul_min_latency; /* min expected uplink latency for first hop (ms) */
	u_int32_t ul_effective_latency; /* current expected uplink latency for first hop (ms) */
	u_int32_t ul_max_latency; /* max expected uplink latency first hop (ms) */
	u_int32_t ul_retxt_level; /* Retransmission metric */
#define IF_CELL_UL_RETXT_LEVEL_NONE     1
#define IF_CELL_UL_RETXT_LEVEL_LOW      2
#define IF_CELL_UL_RETXT_LEVEL_MEDIUM   3
#define IF_CELL_UL_RETXT_LEVEL_HIGH     4
	u_int32_t ul_bytes_lost; /* % of total bytes lost on uplink in Q10 format */
	u_int32_t ul_min_queue_size; /* minimum bytes in queue */
	u_int32_t ul_avg_queue_size; /* average bytes in queue */
	u_int32_t ul_max_queue_size; /* maximum bytes in queue */
	u_int32_t dl_effective_bandwidth; /* Measured downlink bandwidth based on current activity (bps) */
	u_int32_t dl_max_bandwidth; /* Maximum supported downlink bandwidth (bps) */
	u_int32_t config_inactivity_time; /* ms */
	u_int32_t config_backoff_time; /* new connections backoff time in ms */
#define IF_CELL_UL_MSS_RECOMMENDED_NONE 0x0 /* Use default */
#define IF_CELL_UL_MSS_RECOMMENDED_MEDIUM 0x1 /* 1200 byte MSS */
#define IF_CELL_UL_MSS_RECOMMENDED_LOW  0x2 /* 512 byte MSS */
	u_int16_t mss_recommended;
	u_int16_t reserved_1;
	u_int32_t reserved_2;
	u_int64_t reserved_3;
	u_int64_t reserved_4;
	u_int64_t reserved_5;
	u_int64_t reserved_6;
} __attribute__((packed));

struct if_cellular_status {
	union {
		struct if_cellular_status_v1 if_status_v1;
	} if_cell_u;
};

/*
 * These statistics will be provided by the Wifi driver periodically.
 * After sending each report, the driver should start computing again
 * for the next report duration so that the values represent the link
 * status for one report duration.
 */

struct if_wifi_status_v1 {
	u_int32_t valid_bitmask;
#define IF_WIFI_LINK_QUALITY_METRIC_VALID       0x1
#define IF_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID    0x2
#define IF_WIFI_UL_MAX_BANDWIDTH_VALID          0x4
#define IF_WIFI_UL_MIN_LATENCY_VALID            0x8
#define IF_WIFI_UL_EFFECTIVE_LATENCY_VALID      0x10
#define IF_WIFI_UL_MAX_LATENCY_VALID            0x20
#define IF_WIFI_UL_RETXT_LEVEL_VALID            0x40
#define IF_WIFI_UL_ERROR_RATE_VALID             0x80
#define IF_WIFI_UL_BYTES_LOST_VALID             0x100
#define IF_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID    0x200
#define IF_WIFI_DL_MAX_BANDWIDTH_VALID          0x400
#define IF_WIFI_DL_MIN_LATENCY_VALID            0x800
#define IF_WIFI_DL_EFFECTIVE_LATENCY_VALID      0x1000
#define IF_WIFI_DL_MAX_LATENCY_VALID            0x2000
#define IF_WIFI_DL_ERROR_RATE_VALID             0x4000
#define IF_WIFI_CONFIG_FREQUENCY_VALID          0x8000
#define IF_WIFI_CONFIG_MULTICAST_RATE_VALID     0x10000
#define IF_WIFI_CONFIG_SCAN_COUNT_VALID         0x20000
#define IF_WIFI_CONFIG_SCAN_DURATION_VALID      0x40000
	u_int32_t link_quality_metric; /* link quality metric */
	u_int32_t ul_effective_bandwidth; /* Measured uplink bandwidth based on current activity (bps) */
	u_int32_t ul_max_bandwidth; /* Maximum supported uplink bandwidth (bps) */
	u_int32_t ul_min_latency; /* min expected uplink latency for first hop (ms) */
	u_int32_t ul_effective_latency; /* current expected uplink latency for first hop (ms) */
	u_int32_t ul_max_latency; /* max expected uplink latency for first hop (ms) */
	u_int32_t ul_retxt_level; /* Retransmission metric */
#define IF_WIFI_UL_RETXT_LEVEL_NONE     1
#define IF_WIFI_UL_RETXT_LEVEL_LOW      2
#define IF_WIFI_UL_RETXT_LEVEL_MEDIUM   3
#define IF_WIFI_UL_RETXT_LEVEL_HIGH     4
	u_int32_t ul_bytes_lost; /* % of total bytes lost on uplink in Q10 format */
	u_int32_t ul_error_rate; /* % of bytes dropped on uplink after many retransmissions in Q10 format */
	u_int32_t dl_effective_bandwidth; /* Measured downlink bandwidth based on current activity (bps) */
	u_int32_t dl_max_bandwidth; /* Maximum supported downlink bandwidth (bps) */
	/*
	 * The download latency values indicate the time AP may have to wait for the
	 * driver to receive the packet. These values give the range of expected latency
	 * mainly due to co-existence events and channel hopping where the interface
	 * becomes unavailable.
	 */
	u_int32_t dl_min_latency; /* min expected latency for first hop in ms */
	u_int32_t dl_effective_latency; /* current expected latency for first hop in ms */
	u_int32_t dl_max_latency; /* max expected latency for first hop in ms */
	u_int32_t dl_error_rate; /* % of CRC or other errors in Q10 format */
	u_int32_t config_frequency; /* 2.4 or 5 GHz */
#define IF_WIFI_CONFIG_FREQUENCY_2_4_GHZ        1
#define IF_WIFI_CONFIG_FREQUENCY_5_0_GHZ        2
	u_int32_t config_multicast_rate; /* bps */
	u_int32_t scan_count; /* scan count during the previous period */
	u_int32_t scan_duration; /* scan duration in ms */
	u_int64_t reserved_1;
	u_int64_t reserved_2;
	u_int64_t reserved_3;
	u_int64_t reserved_4;
} __attribute__((packed));

struct if_wifi_status {
	union {
		struct if_wifi_status_v1 if_status_v1;
	} if_wifi_u;
};

struct if_link_status {
	u_int32_t       ifsr_version;   /* version of this report */
	u_int32_t       ifsr_len;       /* length of the following struct */
	union {
		struct if_cellular_status ifsr_cell;
		struct if_wifi_status ifsr_wifi;
	} ifsr_u;
};

/*
 * This structure is used to define the parameters for advisory notifications
 * on an interface.
 */
#pragma pack(push, 1)
enum ifnet_interface_advisory_version : uint8_t {
	/*
	 * Initial version with interface advisory report for WiFi interface.
	 */
	IF_INTERFACE_ADVISORY_VERSION_1 = 1,
#if XNU_KERNEL_PRIVATE
	IF_INTERFACE_ADVISORY_VERSION_MIN = IF_INTERFACE_ADVISORY_VERSION_1,
#endif /* XNU_KERNEL_PRIVATE */
	/*
	 * Reorganized the interface advisory structure to separate out
	 * WiFi and Cellular interface specific reports.
	 */
	IF_INTERFACE_ADVISORY_VERSION_2 = 2,
	IF_INTERFACE_ADVISORY_VERSION_CURRENT = IF_INTERFACE_ADVISORY_VERSION_2,
#if XNU_KERNEL_PRIVATE
	IF_INTERFACE_ADVISORY_VERSION_MAX = IF_INTERFACE_ADVISORY_VERSION_2,
#endif /* XNU_KERNEL_PRIVATE */
};

enum ifnet_interface_advisory_direction : uint8_t {
	IF_INTERFACE_ADVISORY_DIRECTION_TX = 1,
	IF_INTERFACE_ADVISORY_DIRECTION_RX = 2,
};

enum ifnet_interface_advisory_interface_type : uint8_t {
	IF_INTERFACE_ADVISORY_INTERFACE_TYPE_WIFI = 1,
#if XNU_KERNEL_PRIVATE
	IF_INTERFACE_ADVISORY_INTERFACE_TYPE_MIN =
	    IF_INTERFACE_ADVISORY_INTERFACE_TYPE_WIFI,
#endif /* XNU_KERNEL_PRIVATE */
	IF_INTERFACE_ADVISORY_INTERFACE_TYPE_CELL = 2,
#if XNU_KERNEL_PRIVATE
	IF_INTERFACE_ADVISORY_INTERFACE_TYPE_MAX =
	    IF_INTERFACE_ADVISORY_INTERFACE_TYPE_CELL,
#endif /* XNU_KERNEL_PRIVATE */
};

struct ifnet_interface_advisory_header {
	/* The current structure version */
	enum ifnet_interface_advisory_version         version;
	/*  Specifies if the advisory is for transmit or receive path */
	enum ifnet_interface_advisory_direction       direction;
	/* Interface type */
	enum ifnet_interface_advisory_interface_type  interface_type;
	/* reserved for future use */
	uint8_t                                       reserved;
};

enum ifnet_interface_advisory_rate_trend : int32_t {
	IF_INTERFACE_ADVISORY_RATE_SUGGESTION_RAMP_UP = INT32_MAX,
	IF_INTERFACE_ADVISORY_RATE_SUGGESTION_RAMP_DOWN = INT32_MIN,
	IF_INTERFACE_ADVISORY_RATE_SUGGESTION_RAMP_NEUTRAL = 0,
};

struct ifnet_interface_advisory_capacity {
	/*
	 * suggestion for data rate change to keep the latency low.
	 * unit: bits per second (bps)
	 * NOTE: if the interface cannot provide suggestions in
	 * terms of bps, it should use the following values:
	 * INT32_MAX : ramp up
	 * INT32_MIN : ramp down
	 * 0         : neutral
	 */
	enum ifnet_interface_advisory_rate_trend  rate_trend_suggestion;
	/*
	 * Time of the issue of advisory.
	 * Timestamp should be in the host domain.
	 * unit: mach absolute time
	 */
	uint64_t    timestamp;
	/*
	 * Maximum theoretical bandwidth of the interface.
	 * unit: bits per second (bps)
	 */
	uint64_t    max_bandwidth;
	/*
	 * Total bytes sent or received on the interface.
	 * wrap around possible and the application should account for that.
	 * unit: byte
	 */
	uint64_t    total_byte_count;
	/*
	 * average throughput observed at the driver stack.
	 * unit: bits per second (bps)
	 */
	uint64_t    average_throughput;
	/*
	 * flushable queue size at the driver.
	 * should be set to UINT32_MAX if not available.
	 * unit: byte
	 */
	uint32_t    flushable_queue_size;
	/*
	 * non flushable queue size at the driver.
	 * should be set to UINT32_MAX if not available.
	 * unit: byte
	 */
	uint32_t    non_flushable_queue_size;
	/*
	 * average delay observed at the interface.
	 * unit: milliseconds (ms)
	 */
	uint32_t    average_delay;
};

enum ifnet_interface_advisory_wifi_freq_band : uint8_t {
	IF_INTERFACE_ADVISORY_FREQ_BAND_NOT_AVAIL =  0,
	IF_INTERFACE_ADVISORY_FREQ_BAND_WIFI_24GHZ = 1,
	IF_INTERFACE_ADVISORY_FREQ_BAND_WIFI_5GHZ =  2,
	IF_INTERFACE_ADVISORY_FREQ_BAND_WIFI_6GHZ =  3,
};

/*
 * This structure is used to define the parameters for advisory notifications
 * that are specific for WiFi interface.
 */
struct ifnet_interface_advisory_wifi_context {
	/*
	 * Current frequency band (enumeration).
	 */
	enum ifnet_interface_advisory_wifi_freq_band  frequency_band;
	/*
	 * Intermittent WiFi state [true(1)/false(0)]
	 */
	uint8_t     intermittent_state;
	/*
	 * Estimated period for which intermittent state is expected to last.
	 * 1 tick -> 1 ms UNDEF => UINT16_MAX
	 */
	uint16_t    estimated_intermittent_period;
	/*
	 * Expected wifi outage period during intermittent state
	 * 1 tick -> 1 ms UNDEF => UINT16_MAX
	 */
	uint16_t    single_outage_period;
	/*
	 * WiFi-BT coexistence, 1-ON, 0-OFF
	 */
	uint8_t     bt_coex;
	/*
	 * on scale of 1 to 5
	 */
	uint8_t     quality_score_delay;
	/*
	 * on scale of 1 to 5
	 */
	uint8_t     quality_score_loss;
	/*
	 * on scale of 1 to 5
	 */
	uint8_t     quality_score_channel;
	/*
	 * bitmap of all radio contenders.
	 */
#define IF_INTERFACE_ADVISORY_WIFI_RADIO_COEX_BT    0x01
#define IF_INTERFACE_ADVISORY_WIFI_RADIO_COEX_AWDL  0x02
	uint8_t     radio_coex;
	/*
	 * time available to WiFi since last notification (in ms).
	 */
	uint16_t    wlan_duty_cycle;
	/*
	 * bitrate information for each queue (in Kbps).
	 */
#define IF_INTERFACE_ADVISORY_WIFI_TX_QUEUE_COUNT  6
	uint32_t    wifi_observed_tx_bitrate[IF_INTERFACE_ADVISORY_WIFI_TX_QUEUE_COUNT];
};

/*
 * This structure is used to define the parameters for advisory notifications
 * that are specific for Cellular interface.
 */
struct ifnet_interface_advisory_cell_context {
	/*
	 * Radio Access Technology
	 */
	uint8_t     radio_access_technology;
	/*
	 * Received Reference Signal Received level (RSRP dBm)
	 */
	int16_t     reference_signal_level;
	/*
	 * Received Signal strength level (RSSI dBm)
	 */
	int16_t     signal_level;
	/*
	 * Received signal quality (SNR dB).
	 */
	int8_t      signal_quality;
	/*
	 * Uplink Block Error Rate %
	 */
	uint8_t     uplink_bler;
	/*
	 * Downlink Block Error Rate %
	 */
	uint8_t     downlink_bler;
	/*
	 * Bandwidth Limitation Type. I.e. TTI-B.
	 */
	uint8_t     bandwidth_limitation_indication;
	/*
	 * Discontinuous reception state: CDRX on/off.
	 */
	uint8_t     cdrx_state;
	/*
	 * Discontinuous reception cycle in ms.
	 */
	uint16_t    cdrx_cycle;
	/*
	 * Approximate outage period when not known
	 */
	uint16_t    estimated_outage_period;
	/*
	 * Cellular outage state: i.e. handover in progress.
	 *     0 - no outage
	 *     1 - outage.
	 */
#define IF_INTERFACE_ADVISORY_CELL_OUTAGE_STATE_NO     0
#define IF_INTERFACE_ADVISORY_CELL_OUTAGE_STATE_YES    1
	uint8_t     outage_state;
	/*
	 * padding for alignment.
	 */
	uint8_t     __pad;
};

struct ifnet_interface_advisory {
	union {
		struct { /* version 1 structure (to be deprecated) */
			/* The current structure version */
			uint8_t     version;
			/*  Specifies if the advisory is for transmit or receive path */
			uint8_t     direction;
			/* reserved for future use */
			uint16_t    _reserved;
			/*
			 * suggestion for data rate change to keep the latency low.
			 * unit: bits per second (bps)
			 * NOTE: if the interface cannot provide suggestions in terms of bps,
			 * it should use the following values:
			 * INT32_MAX : ramp up
			 * INT32_MIN : ramp down
			 * 0         : neutral
			 */
			int32_t     rate_trend_suggestion;
			/*
			 * Time of the issue of advisory.
			 * Timestamp should be in the host domain.
			 * unit: mach absolute time
			 */
			uint64_t    timestamp;
			/*
			 * Maximum theoretical bandwidth of the interface.
			 * unit: bits per second (bps)
			 */
			uint64_t    max_bandwidth;
			/*
			 * Total bytes sent or received on the interface.
			 * wrap around possible and the application should account for that.
			 * unit: byte
			 */
			uint64_t    total_byte_count;
			/*
			 * average throughput observed at the driver stack.
			 * unit: bits per second (bps)
			 */
			uint64_t    average_throughput;
			/*
			 * flushable queue size at the driver.
			 * should be set to UINT32_MAX if not available.
			 * unit: byte
			 */
			uint32_t    flushable_queue_size;
			/*
			 * non flushable queue size at the driver.
			 * should be set to UINT32_MAX if not available.
			 * unit: byte
			 */
			uint32_t    non_flushable_queue_size;
			/*
			 * average delay observed at the interface.
			 * unit: milliseconds (ms)
			 */
			uint32_t    average_delay;
			/*
			 * Current frequency band (enumeration).
			 */
			uint8_t    frequency_band;
			/*
			 * Intermittent WiFi state [true(1)/false(0)]
			 */
			uint8_t     intermittent_state;
			/*
			 * Estimated period for which intermittent state is expected to last.
			 * 1 tick -> 1 ms UNDEF => UINT16_MAX
			 */
			uint16_t    estimated_intermittent_period;
			/*
			 * Expected wifi outage period during intermittent state
			 * 1 tick -> 1 ms UNDEF => UINT16_MAX
			 */
			uint16_t    single_outage_period;

			/*
			 * WiFi-BT coexistence, 1-ON, 0-OFF
			 */
			uint8_t     bt_coex;
			/*
			 * on scale of 1 to 5
			 */
			uint8_t     quality_score_delay;
			/*
			 * on scale of 1 to 5
			 */
			uint8_t     quality_score_loss;
			/*
			 * on scale of 1 to 5
			 */
			uint8_t     quality_score_channel;
		};

		struct { /* version 2 structure */
			struct ifnet_interface_advisory_header    header;
			struct ifnet_interface_advisory_capacity  capacity;
			union {
				struct ifnet_interface_advisory_wifi_context    wifi_context;
				struct ifnet_interface_advisory_cell_context    cell_context;
			};
		};
	};
} __attribute__((aligned(sizeof(uint64_t))));
#pragma pack(pop)

/*
 * Definitions related to traffic steering
 */
#pragma pack(push, 1)

/* Supported types */
/* Reserving 1 for link layer */
#define IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET 2

/* Supported flags */
#define IFNET_TRAFFIC_DESCRIPTOR_FLAG_INBOUND  0x0001
#define IFNET_TRAFFIC_DESCRIPTOR_FLAG_OUTBOUND 0x0002

struct ifnet_traffic_descriptor_common {
	uint8_t     itd_type;
	uint8_t     _reserved;
	uint16_t    itd_len; /* length of entire struct (common + td-specific) */
	uint32_t    itd_flags;
};

#define IFNET_TRAFFIC_DESCRIPTOR_INET_IPVER 0x01
#define IFNET_TRAFFIC_DESCRIPTOR_INET_PROTO 0x02
#define IFNET_TRAFFIC_DESCRIPTOR_INET_LADDR 0x04
#define IFNET_TRAFFIC_DESCRIPTOR_INET_RADDR 0x08
#define IFNET_TRAFFIC_DESCRIPTOR_INET_LPORT 0x10
#define IFNET_TRAFFIC_DESCRIPTOR_INET_RPORT 0x20

struct ifnet_ip_addr {
	union {
		uint8_t  addr8[16];
		uint16_t addr16[8];
		uint32_t addr32[4];
	};
};
#define iia_v4addr addr32[3]

struct ifnet_traffic_descriptor_inet {
	struct ifnet_traffic_descriptor_common inet_common;
	uint8_t     inet_mask;
	uint8_t     inet_ipver; /* IPVERSION or IPV6_VERSION */
	uint8_t     inet_proto; /* IPPROTO_TCP or IPPROTO_UDP */
	uint8_t     _reserved;
	struct ifnet_ip_addr inet_laddr;
	struct ifnet_ip_addr inet_raddr;
	uint16_t    inet_lport;
	uint16_t    inet_rport;
};

#define IFNET_TRAFFIC_RULE_ACTION_STEER 1
struct ifnet_traffic_rule_action {
	uint8_t     ra_type;
	uint8_t     _reserved;
	uint16_t    ra_len;
};

struct ifnet_traffic_rule_action_steer {
	struct ifnet_traffic_rule_action ras_common;
	uint64_t    ras_qset_id;
};
#pragma pack(pop)

#pragma pack()

#endif /* !_NET_IF_VAR_STATUS_H_ */
