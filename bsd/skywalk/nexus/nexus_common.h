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

#ifndef _SKYWALK_NEXUS_COMMON_H_
#define _SKYWALK_NEXUS_COMMON_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
/*
 * Routines common to kernel and userland.  This file is intended to be
 * included by code implementing the nexus controller logic, in particular,
 * the Skywalk kernel and libsyscall code.
 */

#include <skywalk/os_nexus_private.h>
#include <sys/errno.h>

#ifndef KERNEL
#if !defined(LIBSYSCALL_INTERFACE)
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#endif /* !KERNEL */

__attribute__((always_inline))
static inline int
__nexus_attr_set(const nexus_attr_t nxa, const nexus_attr_type_t type,
    const uint64_t value)
{
	int err = 0;

	if (nxa == NULL) {
		return EINVAL;
	}

	switch (type) {
	case NEXUS_ATTR_TX_RINGS:
		nxa->nxa_requested |= NXA_REQ_TX_RINGS;
		nxa->nxa_tx_rings = value;
		break;

	case NEXUS_ATTR_RX_RINGS:
		nxa->nxa_requested |= NXA_REQ_RX_RINGS;
		nxa->nxa_rx_rings = value;
		break;

	case NEXUS_ATTR_TX_SLOTS:
		nxa->nxa_requested |= NXA_REQ_TX_SLOTS;
		nxa->nxa_tx_slots = value;
		break;

	case NEXUS_ATTR_RX_SLOTS:
		nxa->nxa_requested |= NXA_REQ_RX_SLOTS;
		nxa->nxa_rx_slots = value;
		break;

	case NEXUS_ATTR_SLOT_BUF_SIZE:
		nxa->nxa_requested |= NXA_REQ_BUF_SIZE;
		nxa->nxa_buf_size = value;
		break;

	case NEXUS_ATTR_ANONYMOUS:
		nxa->nxa_requested |= NXA_REQ_ANONYMOUS;
		nxa->nxa_anonymous = value;
		break;

	case NEXUS_ATTR_PIPES:
		nxa->nxa_requested |= NXA_REQ_PIPES;
		nxa->nxa_pipes = value;
		break;

	case NEXUS_ATTR_EXTENSIONS:
		nxa->nxa_requested |= NXA_REQ_EXTENSIONS;
		nxa->nxa_extensions = value;
		break;

	case NEXUS_ATTR_MHINTS:
		nxa->nxa_requested |= NXA_REQ_MHINTS;
		nxa->nxa_mhints = value;
		break;

	case NEXUS_ATTR_QMAP:
		nxa->nxa_requested |= NXA_REQ_QMAP;
		nxa->nxa_qmap = value;
		break;

	case NEXUS_ATTR_IFINDEX:
#if !defined(LIBSYSCALL_INTERFACE)
		nxa->nxa_requested |= NXA_REQ_IFINDEX;
		nxa->nxa_ifindex = value;
#else /* LIBSYSCALL_INTERFACE */
		err = ENOTSUP;
#endif /* LIBSYSCALL_INTERFACE */
		break;

	case NEXUS_ATTR_USER_CHANNEL:
		nxa->nxa_requested |= NXA_REQ_USER_CHANNEL;
		nxa->nxa_user_channel = value;
		break;

	case NEXUS_ATTR_MAX_FRAGS:
		nxa->nxa_requested |= NXA_REQ_MAX_FRAGS;
		nxa->nxa_max_frags = value;
		break;

	case NEXUS_ATTR_REJECT_ON_CLOSE:
		nxa->nxa_requested |= NXA_REQ_REJECT_ON_CLOSE;
		nxa->nxa_reject_on_close = (value != 0);
		break;

	case NEXUS_ATTR_FLOWADV_MAX:
	case NEXUS_ATTR_STATS_SIZE:
	case NEXUS_ATTR_SLOT_META_SIZE:
	case NEXUS_ATTR_CHECKSUM_OFFLOAD:
	case NEXUS_ATTR_USER_PACKET_POOL:
	case NEXUS_ATTR_ADV_SIZE:
		err = ENOTSUP;
		break;

	default:
		err = EINVAL;
		break;
	}

	return err;
}

__attribute__((always_inline))
static inline int
__nexus_attr_get(const nexus_attr_t nxa, const nexus_attr_type_t type,
    uint64_t *value)
{
	int err = 0;

	if (nxa == NULL || value == NULL) {
		return EINVAL;
	}

	switch (type) {
	case NEXUS_ATTR_TX_RINGS:
		*value = nxa->nxa_tx_rings;
		break;

	case NEXUS_ATTR_RX_RINGS:
		*value = nxa->nxa_rx_rings;
		break;

	case NEXUS_ATTR_TX_SLOTS:
		*value = nxa->nxa_tx_slots;
		break;

	case NEXUS_ATTR_RX_SLOTS:
		*value = nxa->nxa_rx_slots;
		break;

	case NEXUS_ATTR_SLOT_BUF_SIZE:
		*value = nxa->nxa_buf_size;
		break;

	case NEXUS_ATTR_SLOT_META_SIZE:
		*value = nxa->nxa_meta_size;
		break;

	case NEXUS_ATTR_STATS_SIZE:
		*value = nxa->nxa_stats_size;
		break;

	case NEXUS_ATTR_FLOWADV_MAX:
		*value = nxa->nxa_flowadv_max;
		break;

	case NEXUS_ATTR_ANONYMOUS:
		*value = nxa->nxa_anonymous;
		break;

	case NEXUS_ATTR_PIPES:
		*value = nxa->nxa_pipes;
		break;

	case NEXUS_ATTR_EXTENSIONS:
		*value = nxa->nxa_extensions;
		break;

	case NEXUS_ATTR_MHINTS:
		*value = nxa->nxa_mhints;
		break;

	case NEXUS_ATTR_IFINDEX:
		*value = nxa->nxa_ifindex;
		break;

	case NEXUS_ATTR_QMAP:
		*value = nxa->nxa_qmap;
		break;

	case NEXUS_ATTR_CHECKSUM_OFFLOAD:
		*value = nxa->nxa_checksum_offload;
		break;

	case NEXUS_ATTR_USER_PACKET_POOL:
		*value = nxa->nxa_user_packet_pool;
		break;

	case NEXUS_ATTR_ADV_SIZE:
		*value = nxa->nxa_nexusadv_size;
		break;

	case NEXUS_ATTR_USER_CHANNEL:
		*value = nxa->nxa_user_channel;
		break;

	case NEXUS_ATTR_MAX_FRAGS:
		*value = nxa->nxa_max_frags;
		break;

	case NEXUS_ATTR_REJECT_ON_CLOSE:
		*value = nxa->nxa_reject_on_close;
		break;

	default:
		err = EINVAL;
		break;
	}

	return err;
}

__attribute__((always_inline))
static inline void
__nexus_attr_from_params(nexus_attr_t nxa, const struct nxprov_params *p)
{
	bzero(nxa, sizeof(*nxa));
	nxa->nxa_tx_rings = p->nxp_tx_rings;
	nxa->nxa_rx_rings = p->nxp_rx_rings;
	nxa->nxa_tx_slots = p->nxp_tx_slots;
	nxa->nxa_rx_slots = p->nxp_rx_slots;
	nxa->nxa_buf_size = p->nxp_buf_size;
	nxa->nxa_meta_size = p->nxp_meta_size;
	nxa->nxa_stats_size = p->nxp_stats_size;
	nxa->nxa_flowadv_max = p->nxp_flowadv_max;
	nxa->nxa_anonymous = !!(p->nxp_flags & NXPF_ANONYMOUS);
	nxa->nxa_pipes = p->nxp_pipes;
	nxa->nxa_extensions = p->nxp_extensions;
	nxa->nxa_mhints = p->nxp_mhints;
	nxa->nxa_ifindex = p->nxp_ifindex;
	nxa->nxa_qmap = p->nxp_qmap;
	nxa->nxa_checksum_offload = (p->nxp_capabilities &
	    NXPCAP_CHECKSUM_PARTIAL) ? 1 : 0;
	nxa->nxa_user_packet_pool = (p->nxp_capabilities &
	    NXPCAP_USER_PACKET_POOL) ? 1 : 0;
	nxa->nxa_nexusadv_size = p->nxp_nexusadv_size;
	nxa->nxa_user_channel = !!(p->nxp_flags & NXPF_USER_CHANNEL);
	nxa->nxa_max_frags = p->nxp_max_frags;
	nxa->nxa_reject_on_close = (p->nxp_reject_on_close != 0);
}

__attribute__((always_inline))
static inline int
__nexus_provider_reg_prepare(struct nxprov_reg *reg, const nexus_name_t name,
    const nexus_type_t type, const nexus_attr_t nxa)
{
	struct nxprov_params *p = &reg->nxpreg_params;
	int err = 0;

	bzero(reg, sizeof(*reg));
	reg->nxpreg_version = NXPROV_REG_CURRENT_VERSION;
	p->nxp_namelen = (uint32_t)strlcpy((char *)p->nxp_name,
	    (const char *)name, sizeof(nexus_name_t));
	if (p->nxp_namelen == 0) {
		err = EINVAL;
		goto done;
	}
	p->nxp_type = type;
	if (nxa != NULL) {
		if (nxa->nxa_requested & NXA_REQ_TX_RINGS) {
			reg->nxpreg_requested |= NXPREQ_TX_RINGS;
			p->nxp_tx_rings = (uint32_t)nxa->nxa_tx_rings;
		}
		if (nxa->nxa_requested & NXA_REQ_RX_RINGS) {
			reg->nxpreg_requested |= NXPREQ_RX_RINGS;
			p->nxp_rx_rings = (uint32_t)nxa->nxa_rx_rings;
		}
		if (nxa->nxa_requested & NXA_REQ_TX_SLOTS) {
			reg->nxpreg_requested |= NXPREQ_TX_SLOTS;
			p->nxp_tx_slots = (uint32_t)nxa->nxa_tx_slots;
		}
		if (nxa->nxa_requested & NXA_REQ_RX_SLOTS) {
			reg->nxpreg_requested |= NXPREQ_RX_SLOTS;
			p->nxp_rx_slots = (uint32_t)nxa->nxa_rx_slots;
		}
		if (nxa->nxa_requested & NXA_REQ_BUF_SIZE) {
			reg->nxpreg_requested |= NXPREQ_BUF_SIZE;
			p->nxp_buf_size = (uint32_t)nxa->nxa_buf_size;
		}
		if (nxa->nxa_requested & NXA_REQ_ANONYMOUS) {
			reg->nxpreg_requested |= NXPREQ_ANONYMOUS;
			if (nxa->nxa_anonymous != 0) {
				p->nxp_flags |= NXPF_ANONYMOUS;
			} else {
				p->nxp_flags &= (uint32_t)~NXPF_ANONYMOUS;
			}
		}
		if (nxa->nxa_requested & NXA_REQ_PIPES) {
			reg->nxpreg_requested |= NXPREQ_PIPES;
			p->nxp_pipes = (uint32_t)nxa->nxa_pipes;
		}
		if (nxa->nxa_requested & NXA_REQ_EXTENSIONS) {
			reg->nxpreg_requested |= NXPREQ_EXTENSIONS;
			p->nxp_extensions = (uint32_t)nxa->nxa_extensions;
		}
		if (nxa->nxa_requested & NXA_REQ_MHINTS) {
			reg->nxpreg_requested |= NXPREQ_MHINTS;
			p->nxp_mhints = (uint32_t)nxa->nxa_mhints;
		}
		if (nxa->nxa_requested & NXA_REQ_QMAP) {
			if (type != NEXUS_TYPE_NET_IF) {
				err = EINVAL;
				goto done;
			}
			if ((nxa->nxa_qmap == NEXUS_QMAP_TYPE_WMM) &&
			    (reg->nxpreg_params.nxp_tx_rings !=
			    NEXUS_NUM_WMM_QUEUES)) {
				err = EINVAL;
				goto done;
			}
			reg->nxpreg_requested |= NXPREQ_QMAP;
			p->nxp_qmap = (uint32_t)nxa->nxa_qmap;
		}
		if (nxa->nxa_requested & NXA_REQ_IFINDEX) {
			if (type != NEXUS_TYPE_NET_IF) {
				err = EINVAL;
				goto done;
			}
			reg->nxpreg_requested |= NXPREQ_IFINDEX;
			p->nxp_ifindex = (uint32_t)nxa->nxa_ifindex;
		}
		if (nxa->nxa_requested & NXA_REQ_USER_CHANNEL) {
			reg->nxpreg_requested |= NXPREQ_USER_CHANNEL;
			if (nxa->nxa_user_channel != 0) {
				p->nxp_flags |= NXPF_USER_CHANNEL;
			} else {
				p->nxp_flags &= (uint32_t)~NXPF_USER_CHANNEL;
			}
		}
		if (nxa->nxa_requested & NXA_REQ_MAX_FRAGS) {
			if ((type != NEXUS_TYPE_NET_IF) &&
			    (type != NEXUS_TYPE_FLOW_SWITCH)) {
				err = EINVAL;
				goto done;
			}
			reg->nxpreg_requested |= NXPREQ_MAX_FRAGS;
			p->nxp_max_frags = (uint32_t)nxa->nxa_max_frags;
		}
		if (nxa->nxa_requested & NXA_REQ_REJECT_ON_CLOSE) {
			if (type != NEXUS_TYPE_USER_PIPE) {
				err = EINVAL;
				goto done;
			}
			reg->nxpreg_requested |= NXPREQ_REJECT_ON_CLOSE;
			p->nxp_reject_on_close =
			    (nxa->nxa_reject_on_close != 0);
		}
	}
done:
	return err;
}

__attribute__((always_inline))
static inline void
__nexus_bind_req_prepare(struct nx_bind_req *nbr, const uuid_t nx_uuid,
    const nexus_port_t port, const pid_t pid, const uuid_t exec_uuid,
    const void *key, const uint32_t key_len, const uint32_t bind_flags)
{
	bzero(nbr, sizeof(*nbr));
	if (nx_uuid != NULL) {
		bcopy(nx_uuid, nbr->nb_nx_uuid, sizeof(uuid_t));
	}
	if (exec_uuid != NULL) {
		bcopy(exec_uuid, nbr->nb_exec_uuid, sizeof(uuid_t));
	}
	nbr->nb_port = port;
	nbr->nb_pid = pid;
	if (bind_flags & NEXUS_BIND_PID) {
		nbr->nb_flags |= NBR_MATCH_PID;
	}
	if (bind_flags & NEXUS_BIND_EXEC_UUID) {
		nbr->nb_flags |= NBR_MATCH_EXEC_UUID;
	}
	if (bind_flags & NEXUS_BIND_KEY) {
		nbr->nb_flags |= NBR_MATCH_KEY;
		nbr->nb_key = (user_addr_t)key;
		nbr->nb_key_len = key_len;
	}
}

__attribute__((always_inline))
static inline void
__nexus_unbind_req_prepare(struct nx_unbind_req *nbu, const uuid_t nx_uuid,
    const nexus_port_t port)
{
	bzero(nbu, sizeof(*nbu));
	if (nx_uuid != NULL) {
		bcopy(nx_uuid, nbu->nu_nx_uuid, sizeof(uuid_t));
	}
	nbu->nu_port = port;
}

__attribute__((always_inline))
static inline void
__nexus_config_req_prepare(struct nx_cfg_req *ncr, const uuid_t nx_uuid,
    const nxcfg_cmd_t cmd, const void *arg, const size_t arg_len)
{
	VERIFY(arg_len <= UINT32_MAX);
	bzero(ncr, sizeof(*ncr));
	if (nx_uuid != NULL) {
		bcopy(nx_uuid, ncr->nc_nx_uuid, sizeof(uuid_t));
	}
	ncr->nc_cmd = cmd;
	ncr->nc_req_len = (uint32_t)arg_len;
	ncr->nc_req = (user_addr_t)arg;
}

#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_NEXUS_COMMON_H_ */
