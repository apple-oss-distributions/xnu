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


#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
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
