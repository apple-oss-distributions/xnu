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

#include <skywalk/os_skywalk_private.h>
#include <IOKit/IOBSD.h>

static int
nxioctl_check_entitlement(u_long cmd)
{
	boolean_t entitled = FALSE;

	if (kauth_cred_issuser(kauth_cred_get())) {
		return 0;
	}
	switch (cmd) {
	case NXIOC_ADD_TRAFFIC_RULE_INET:
	case NXIOC_REMOVE_TRAFFIC_RULE:
		entitled = IOCurrentTaskHasEntitlement(
			NXCTL_TRAFFIC_RULE_WRITE_ENTITLEMENT);
		break;
	case NXIOC_GET_TRAFFIC_RULES:
		entitled = IOCurrentTaskHasEntitlement(
			NXCTL_TRAFFIC_RULE_READ_ENTITLEMENT);
		break;
	default:
		SK_ERR("invalid command %x", cmd);
		return ENOTSUP;
	}
	return entitled ? 0 : EPERM;
}

int
nxioctl(struct nxctl *nxctl, u_long cmd, caddr_t data, proc_t procp)
{
	int err;

	if ((err = nxioctl_check_entitlement(cmd)) != 0) {
		return err;
	}
	switch (cmd) {
	case NXIOC_ADD_TRAFFIC_RULE_INET:
		return nxioctl_add_traffic_rule_inet(nxctl, data, procp);
	case NXIOC_REMOVE_TRAFFIC_RULE:
		return nxioctl_remove_traffic_rule(nxctl, data, procp);
	case NXIOC_GET_TRAFFIC_RULES:
		return nxioctl_get_traffic_rules(nxctl, data, procp);
	default:
		SK_ERR("invalid command %x", cmd);
		return ENOTSUP;
	}
}
