/*
 * Copyright (c) 2015-2017 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_NEXUS_NETIF_HOST_H_
#define _SKYWALK_NEXUS_NETIF_HOST_H_

#include <skywalk/os_skywalk_private.h>

__BEGIN_DECLS
extern int nx_netif_host_na_activate(struct nexus_adapter *,
    na_activate_mode_t);
extern int nx_netif_host_krings_create(struct nexus_adapter *,
    struct kern_channel *);
extern void nx_netif_host_krings_delete(struct nexus_adapter *,
    struct kern_channel *, boolean_t);
extern int nx_netif_host_na_rxsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
extern int nx_netif_host_na_txsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
extern int nx_netif_host_na_special(struct nexus_adapter *,
    struct kern_channel *, struct chreq *, nxspec_cmd_t);
extern int nx_netif_host_output(struct ifnet *, struct mbuf *);
__END_DECLS
#endif /* _SKYWALK_NEXUS_NETIF_HOST_H_ */
