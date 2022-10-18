/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_NEXUS_IOCTL_H_
#define _SKYWALK_NEXUS_IOCTL_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
/*
 * Routines common to kernel and userland.  This file is intended to be
 * included by code implementing the nexus controller ioctl logic,
 * in particular, the Skywalk kernel and libsyscall code.
 */
#include <skywalk/os_nexus_private.h>
#include <sys/ioctl.h>
#include <sys/errno.h>

#ifndef KERNEL
#if !defined(LIBSYSCALL_INTERFACE)
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#else
extern int nxioctl(struct nxctl *, u_long, caddr_t, proc_t);
extern int nxioctl_add_traffic_rule_inet(struct nxctl *, caddr_t, proc_t);
extern int nxioctl_remove_traffic_rule(struct nxctl *, caddr_t, proc_t);
extern int nxioctl_get_traffic_rules(struct nxctl *, caddr_t, proc_t);
#endif /* !KERNEL */

/*
 * Naming convention:
 * ioctl arguments (structures included in NXIOC_* definitions) have the
 * _iocargs suffix. The code in sys_generic.c:ioctl() handles the copyin/out
 * of these arguments.
 */
#define NXIOC_ADD_TRAFFIC_RULE_FLAG_PERSIST 0x0001
struct nxctl_add_traffic_rule_inet_iocargs {
	char atri_ifname[IFNAMSIZ];
	struct ifnet_traffic_descriptor_inet atri_td;
	struct ifnet_traffic_rule_action_steer atri_ra;
	uint32_t atri_flags;
	uuid_t atri_uuid;
};
#define NXIOC_ADD_TRAFFIC_RULE_INET \
    _IOWR('n', 1, struct nxctl_add_traffic_rule_inet_iocargs)

struct nxctl_remove_traffic_rule_iocargs {
	uuid_t rtr_uuid;
};
#define NXIOC_REMOVE_TRAFFIC_RULE \
    _IOW('n', 2, struct nxctl_remove_traffic_rule_iocargs)

/*
 * nxctl_get_traffic_rules_iocargs.gtr_buf holds an array of
 * nxctl_traffic_rule_inet_iocinfo. This does not have the _iocargs suffix
 * because the structure is not part of a NXIOC* definition. It has an _iocinfo
 * suffix to denote that it is shared between kernel and userspace.
 */
#define NTR_PROCNAME_SZ 64
struct nxctl_traffic_rule_generic_iocinfo {
	uuid_t trg_uuid;
	char trg_procname[NTR_PROCNAME_SZ];
	char trg_ifname[IFNAMSIZ];
};
struct nxctl_traffic_rule_inet_iocinfo {
	struct nxctl_traffic_rule_generic_iocinfo tri_common;
	struct ifnet_traffic_descriptor_inet tri_td;
	struct ifnet_traffic_rule_action_steer tri_ra;
};
struct nxctl_get_traffic_rules_iocargs {
	uint8_t gtr_type;
	uint32_t gtr_size;
	uint32_t gtr_count;
	union {
		void *gtr_buf;
		uint64_t gtr_buf64;
	};
};
#define NXIOC_GET_TRAFFIC_RULES \
    _IOWR('n', 3, struct nxctl_get_traffic_rules_iocargs)

#define NXCTL_TRAFFIC_RULE_READ_ENTITLEMENT  "com.apple.private.skywalk.traffic_rule.read"
#define NXCTL_TRAFFIC_RULE_WRITE_ENTITLEMENT "com.apple.private.skywalk.traffic_rule.write"

#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_NEXUS_IOCTL_H_ */
