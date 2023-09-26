/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <net/if_var.h>
#include <skywalk/os_skywalk_private.h>

#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */

nexus_attr_t
os_nexus_attr_create(void)
{
	struct nexus_attr *nxa;

	nxa = malloc(sizeof(*nxa));
	if (nxa != NULL) {
		bzero(nxa, sizeof(*nxa));
	}
	return nxa;
}

nexus_attr_t
os_nexus_attr_clone(const nexus_attr_t nxa)
{
	struct nexus_attr *nnxa = NULL;

	nnxa = os_nexus_attr_create();
	if (nnxa != NULL && nxa != NULL) {
		bcopy(nxa, nnxa, sizeof(*nnxa));
	}

	return nnxa;
}

int
os_nexus_attr_set(const nexus_attr_t nxa, const nexus_attr_type_t type,
    const uint64_t value)
{
	return __nexus_attr_set(nxa, type, value);
}

int
os_nexus_attr_get(const nexus_attr_t nxa, const nexus_attr_type_t type,
    uint64_t *value)
{
	return __nexus_attr_get(nxa, type, value);
}

void
os_nexus_attr_destroy(nexus_attr_t nxa)
{
	free(nxa);
}

nexus_controller_t
os_nexus_controller_create(void)
{
	struct nexus_controller *ncd = NULL;
	struct nxctl_init init;
	int fd;

	bzero(&init, sizeof(init));
	init.ni_version = NEXUSCTL_INIT_CURRENT_VERSION;

	fd = __nexus_open(&init, sizeof(init));
	if (fd == -1) {
		goto done;
	}

	ncd = malloc(sizeof(*ncd));
	if (ncd == NULL) {
		(void) guarded_close_np(fd, &init.ni_guard);
		goto done;
	}
	bzero(ncd, sizeof(*ncd));
	ncd->ncd_fd = fd;
	ncd->ncd_guard = init.ni_guard;
done:
	return ncd;
}

int
os_nexus_controller_get_fd(const nexus_controller_t ncd)
{
	return ncd->ncd_fd;
}

int
os_nexus_controller_register_provider(const nexus_controller_t ncd,
    const nexus_name_t name, const nexus_type_t type,
    const nexus_attr_t nxa, uuid_t *prov_uuid)
{
	struct nxprov_reg reg;
	int err;

	if ((err = __nexus_provider_reg_prepare(&reg, name, type, nxa)) == 0) {
		err = __nexus_register(ncd->ncd_fd, &reg, sizeof(reg),
		    prov_uuid, sizeof(uuid_t));
	}
	return err;
}

int
os_nexus_controller_deregister_provider(const nexus_controller_t ncd,
    const uuid_t prov_uuid)
{
	return __nexus_deregister(ncd->ncd_fd, prov_uuid, sizeof(uuid_t));
}

int
os_nexus_controller_alloc_provider_instance(const nexus_controller_t ncd,
    const uuid_t prov_uuid, uuid_t *nx_uuid)
{
	return __nexus_create(ncd->ncd_fd, prov_uuid, sizeof(uuid_t),
	           nx_uuid, sizeof(uuid_t));
}

int
os_nexus_controller_free_provider_instance(const nexus_controller_t ncd,
    const uuid_t nx_uuid)
{
	return __nexus_destroy(ncd->ncd_fd, nx_uuid, sizeof(uuid_t));
}

int
os_nexus_controller_bind_provider_instance(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const nexus_port_t port, const pid_t pid,
    const uuid_t exec_uuid, const void *key, const uint32_t key_len,
    uint32_t bind_flags)
{
	struct nx_bind_req nbr;

	__nexus_bind_req_prepare(&nbr, nx_uuid, port, pid, exec_uuid,
	    key, key_len, bind_flags);

	return __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_BIND,
	           &nbr, sizeof(nbr));
}

int
os_nexus_controller_unbind_provider_instance(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const nexus_port_t port)
{
	struct nx_unbind_req nbu;

	__nexus_unbind_req_prepare(&nbu, nx_uuid, port);

	return __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_UNBIND,
	           &nbu, sizeof(nbu));
}

int
os_nexus_controller_read_provider_attr(const nexus_controller_t ncd,
    const uuid_t prov_uuid, nexus_attr_t nxa)
{
	struct nxprov_reg_ent nre;
	uint32_t nre_len = sizeof(nre);
	struct nxprov_params *p = &nre.npre_prov_params;
	int ret = 0;

	if (nxa == NULL) {
		return EINVAL;
	}

	bzero(&nre, sizeof(nre));
	bcopy(prov_uuid, nre.npre_prov_uuid, sizeof(uuid_t));
	ret = __nexus_get_opt(ncd->ncd_fd, NXOPT_NEXUS_PROV_ENTRY,
	    &nre, &nre_len);

	if (ret == 0) {
		__nexus_attr_from_params(nxa, p);
	}

	return ret;
}

static int
add_traffic_rule_inet(const nexus_controller_t ncd,
    const char *ifname, const struct ifnet_traffic_descriptor_inet *td,
    const struct ifnet_traffic_rule_action_steer *ra, const uint32_t flags,
    uuid_t *rule_uuid)
{
	struct nxctl_add_traffic_rule_inet_iocargs args;
	int err;

	bzero(&args, sizeof(args));
	if (ifname != NULL) {
		(void) strlcpy(args.atri_ifname, ifname, IFNAMSIZ);
	}
	bcopy(td, &args.atri_td, sizeof(args.atri_td));
	bcopy(ra, &args.atri_ra, sizeof(args.atri_ra));

	if ((flags & NXCTL_ADD_TRAFFIC_RULE_FLAG_PERSIST) != 0) {
		args.atri_flags |= NXIOC_ADD_TRAFFIC_RULE_FLAG_PERSIST;
	}
	err = ioctl(ncd->ncd_fd, NXIOC_ADD_TRAFFIC_RULE_INET, &args);
	if (err < 0) {
		return errno;
	}
	bcopy(&args.atri_uuid, rule_uuid, sizeof(args.atri_uuid));
	return 0;
}

int
os_nexus_controller_add_traffic_rule(const nexus_controller_t ncd,
    const char *ifname, const struct ifnet_traffic_descriptor_common *td,
    const struct ifnet_traffic_rule_action *ra, const uint32_t flags,
    uuid_t *rule_uuid)
{
	/* only support the steer action for now */
	if (ra->ra_type != IFNET_TRAFFIC_RULE_ACTION_STEER) {
		return ENOTSUP;
	}
	if (ra->ra_len != sizeof(struct ifnet_traffic_rule_action_steer)) {
		return EINVAL;
	}
	/* only support the inet descriptor type for now */
	switch (td->itd_type) {
	case IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET: {
		if (td->itd_len !=
		    sizeof(struct ifnet_traffic_descriptor_inet)) {
			return EINVAL;
		}
		return add_traffic_rule_inet(ncd, ifname,
		           (const struct ifnet_traffic_descriptor_inet *)td,
		           (const struct ifnet_traffic_rule_action_steer *)ra,
		           flags, rule_uuid);
	}
	default:
		return ENOTSUP;
	}
}

int
os_nexus_controller_remove_traffic_rule(const nexus_controller_t ncd,
    const uuid_t rule_uuid)
{
	struct nxctl_remove_traffic_rule_iocargs args;
	int err;

	bzero(&args, sizeof(args));
	bcopy(rule_uuid, &args.rtr_uuid, sizeof(args.rtr_uuid));

	err = ioctl(ncd->ncd_fd, NXIOC_REMOVE_TRAFFIC_RULE, &args);
	if (err < 0) {
		return errno;
	}
	return 0;
}

static void
inet_rule_iterate(void *buf, uint32_t count,
    nexus_traffic_rule_iterator_t itr, void *itr_arg)
{
	struct nxctl_traffic_rule_inet_iocinfo *info = buf;
	struct nxctl_traffic_rule_generic_iocinfo *ginfo;
	struct nexus_traffic_rule_info itr_info;
	uint32_t c;

	for (c = 0; c < count; c++) {
		bzero(&itr_info, sizeof(itr_info));
		ginfo = &info->tri_common;
		itr_info.nri_rule_uuid = &ginfo->trg_uuid;
		itr_info.nri_owner = ginfo->trg_procname;
		itr_info.nri_ifname = ginfo->trg_ifname;
		itr_info.nri_td =
		    (struct ifnet_traffic_descriptor_common *)&info->tri_td;
		itr_info.nri_ra =
		    (struct ifnet_traffic_rule_action *)&info->tri_ra;

		if (!itr(itr_arg, &itr_info)) {
			break;
		}
		info++;
	}
}

struct traffic_rule_type {
	uint8_t tr_type;
	uint32_t tr_size;
	uint32_t tr_count;
	void (*tr_iterate)(void *, uint32_t,
	    nexus_traffic_rule_iterator_t, void *);
};
#define NTRDEFAULTCOUNT 512
static struct traffic_rule_type traffic_rule_types[] = {
	{IFNET_TRAFFIC_DESCRIPTOR_TYPE_INET,
	 sizeof(struct nxctl_traffic_rule_inet_iocinfo),
	 NTRDEFAULTCOUNT, inet_rule_iterate},
};
#define NTRTYPES (sizeof(traffic_rule_types)/sizeof(struct traffic_rule_type))

int
os_nexus_controller_iterate_traffic_rules(const nexus_controller_t ncd,
    nexus_traffic_rule_iterator_t itr, void *itr_arg)
{
	struct nxctl_get_traffic_rules_iocargs args;
	struct traffic_rule_type *t;
	int i, err;

	for (i = 0; i < NTRTYPES; i++) {
		t = &traffic_rule_types[i];
		bzero(&args, sizeof(args));
		args.gtr_type = t->tr_type;
		args.gtr_size = t->tr_size;
		args.gtr_count = t->tr_count;
		args.gtr_buf = malloc(args.gtr_size * args.gtr_count);
		if (args.gtr_buf == NULL) {
			return ENOMEM;
		}
		err = ioctl(ncd->ncd_fd, NXIOC_GET_TRAFFIC_RULES, &args);
		if (err < 0) {
			err = errno;
			free(args.gtr_buf);
			return err;
		}
		if (args.gtr_count > 0) {
			t->tr_iterate(args.gtr_buf, args.gtr_count,
			    itr, itr_arg);
		}
		free(args.gtr_buf);
	}
	return 0;
}

void
os_nexus_controller_destroy(nexus_controller_t ncd)
{
	if (ncd->ncd_fd != -1) {
		(void) guarded_close_np(ncd->ncd_fd, &ncd->ncd_guard);
	}
	free(ncd);
}

int
__os_nexus_ifattach(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const char *ifname, const uuid_t netif_uuid,
    boolean_t host, uuid_t *nx_if_uuid)
{
	struct nx_cfg_req ncr;
	struct nx_spec_req nsr;
	int ret;

	bzero(&nsr, sizeof(nsr));
	if (ifname != NULL) {
		(void) strlcpy(nsr.nsr_name, ifname, sizeof(nsr.nsr_name));
	} else {
		bcopy(netif_uuid, nsr.nsr_uuid, sizeof(uuid_t));
		nsr.nsr_flags |= NXSPECREQ_UUID;
	}

	if (host) {
		nsr.nsr_flags |= NXSPECREQ_HOST;
	}

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_ATTACH,
	    &nsr, sizeof(nsr));

	ret = __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_CONFIG,
	    &ncr, sizeof(ncr));

	if (ret == 0) {
		bcopy(nsr.nsr_if_uuid, nx_if_uuid, sizeof(uuid_t));
	}

	return ret;
}

int
__os_nexus_ifdetach(const nexus_controller_t ncd, const uuid_t nx_uuid,
    const uuid_t nx_if_uuid)
{
	struct nx_cfg_req ncr;
	struct nx_spec_req nsr;

	bzero(&nsr, sizeof(nsr));
	bcopy(nx_if_uuid, nsr.nsr_if_uuid, sizeof(uuid_t));

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_DETACH,
	    &nsr, sizeof(nsr));

	return __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_CONFIG,
	           &ncr, sizeof(ncr));
}

int
__os_nexus_flow_add(const nexus_controller_t ncd, const uuid_t nx_uuid,
    const struct nx_flow_req *nfr)
{
	struct nx_cfg_req ncr;

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_FLOW_ADD,
	    nfr, sizeof(*nfr));

	return __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_CONFIG,
	           &ncr, sizeof(ncr));
}

int
__os_nexus_flow_del(const nexus_controller_t ncd, const uuid_t nx_uuid,
    const struct nx_flow_req *nfr)
{
	struct nx_cfg_req ncr;

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_FLOW_DEL,
	    nfr, sizeof(*nfr));

	return __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_CONFIG,
	           &ncr, sizeof(ncr));
}

static int
__os_nexus_config_flow(const uuid_t nx_uuid, struct nx_flow_req *nfr)
{
	struct nx_cfg_req ncr;

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_FLOW_CONFIG,
	    nfr, sizeof(*nfr));

	return __nexus_set_opt(__OS_NEXUS_SHARED_USER_CONTROLLER_FD,
	           NXOPT_NEXUS_CONFIG, &ncr, sizeof(ncr));
}

int
os_nexus_flow_set_wake_from_sleep(const uuid_t nx_uuid, const uuid_t flow_uuid,
    bool enable)
{
	struct nx_flow_req nfr = {0};
	memcpy(nfr.nfr_flow_uuid, flow_uuid, sizeof(uuid_t));
	nfr.nfr_flags = enable ? 0 : NXFLOWREQF_NOWAKEFROMSLEEP;

	return __os_nexus_config_flow(nx_uuid, &nfr);
}

int
__os_nexus_get_llink_info(const nexus_controller_t ncd, const uuid_t nx_uuid,
    const struct nx_llink_info_req *nlir, size_t len)
{
	struct nx_cfg_req ncr;

	__nexus_config_req_prepare(&ncr, nx_uuid, NXCFG_CMD_GET_LLINK_INFO,
	    nlir, len);

	return __nexus_set_opt(ncd->ncd_fd, NXOPT_NEXUS_CONFIG,
	           &ncr, sizeof(ncr));
}
