/*
 * Copyright (c) 2016-2023 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>

/* automatically register a netagent at constructor time */
static int fsw_netagent = 1;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_kern_skywalk_flowswitch, OID_AUTO, netagent,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_netagent, 0, "");
#endif /* !DEVELOPMENT && !DEBUG */

static packet_svc_class_t
fsw_netagent_tc2sc(uint32_t tc, uint32_t *scp)
{
	uint32_t sc;
	int ret = 0;

	switch (tc) {
	case SO_TC_BK_SYS:
		sc = PKT_SC_BK_SYS;
		break;
	case SO_TC_BK:
		sc = PKT_SC_BK;
		break;
	case SO_TC_BE:
		sc = PKT_SC_BE;
		break;
	case SO_TC_RD:
		sc = PKT_SC_RD;
		break;
	case SO_TC_OAM:
		sc = PKT_SC_OAM;
		break;
	case SO_TC_AV:
		sc = PKT_SC_AV;
		break;
	case SO_TC_RV:
		sc = PKT_SC_RV;
		break;
	case SO_TC_VI:
		sc = PKT_SC_VI;
		break;
	case SO_TC_NETSVC_SIG:
		sc = PKT_SC_SIG;
		break;
	case SO_TC_VO:
		sc = PKT_SC_VO;
		break;
	case SO_TC_CTL:
		sc = PKT_SC_CTL;
		break;
	default:
		sc = PKT_SC_BE;
		ret = -1;
		break;
	}

	*scp = sc;
	return ret;
}

static int
fsw_netagent_flow_add(struct nx_flowswitch *fsw, uuid_t flow_uuid, pid_t pid,
    void *context, struct necp_client_nexus_parameters *cparams,
    void **results, size_t *results_length)
{
	struct nx_flow_req req;
	struct flow_owner *fo = NULL;
	size_t assign_message_length = 0;
	void *assign_message = NULL;
	struct necp_client_endpoint local_endpoint;
	struct necp_client_endpoint remote_endpoint;
	int error;

	ASSERT(cparams != NULL);
	ASSERT(results != NULL && *results == NULL);
	ASSERT(results_length != NULL && *results_length == 0);

	bzero(&req, sizeof(req));
	req.nfr_nx_port = NEXUS_PORT_ANY;
	req.nfr_flowadv_idx = FLOWADV_IDX_NONE;
	bcopy((void *)&cparams->local_addr, (void *)&req.nfr_saddr,
	    sizeof(cparams->local_addr));
	bcopy((void *)&cparams->remote_addr, (void *)&req.nfr_daddr,
	    sizeof(cparams->remote_addr));
	req.nfr_flags = (NXFLOWREQF_TRACK | NXFLOWREQF_FLOWADV);
	req.nfr_ip_protocol = cparams->ip_protocol;
	req.nfr_transport_protocol = cparams->transport_protocol;
	uuid_copy(req.nfr_flow_uuid, flow_uuid);
	uuid_copy(req.nfr_euuid, cparams->euuid);
	req.nfr_epid = cparams->epid;
	req.nfr_policy_id = (uint32_t)cparams->policy_id;

	if (fsw_netagent_tc2sc(cparams->traffic_class,
	    &req.nfr_svc_class) != 0) {
		error = EINVAL;
		goto done;
	}

	if (cparams->allow_qos_marking) {
		req.nfr_flags |= NXFLOWREQF_QOS_MARKING;
	}
	if (cparams->override_address_selection) {
		req.nfr_flags |= NXFLOWREQF_OVERRIDE_ADDRESS_SELECTION;
	}
	if (cparams->use_stable_address) {
		req.nfr_flags |= NXFLOWREQF_USE_STABLE_ADDRESS;
	}
	if (cparams->no_wake_from_sleep) {
		req.nfr_flags |= NXFLOWREQF_NOWAKEFROMSLEEP;
	}
	if (cparams->reuse_port) {
		req.nfr_flags |= NXFLOWREQF_REUSEPORT;
	}

	req.nfr_context = context;
	req.nfr_pid = pid;
	req.nfr_port_reservation = cparams->port_reservation;

	if (cparams->is_demuxable_parent) {
		req.nfr_flags |= NXFLOWREQF_PARENT;
	} else {
		uuid_copy(req.nfr_parent_flow_uuid, cparams->parent_flow_uuid);
		if (cparams->demux_pattern_count > 0) {
			if (cparams->demux_pattern_count > MAX_FLOW_DEMUX_PATTERN) {
				error = EINVAL;
				goto done;
			}

			_CASSERT(sizeof(struct necp_demux_pattern) == sizeof(struct flow_demux_pattern));
			for (int i = 0; i < cparams->demux_pattern_count; i++) {
				memcpy(&req.nfr_flow_demux_patterns[i], &cparams->demux_patterns[i],
				    sizeof(struct flow_demux_pattern));
			}
			req.nfr_flow_demux_count = cparams->demux_pattern_count;
		}
	}

	ASSERT(req.nfr_flags & NXFLOWREQF_FLOWADV);
	fo = fsw_flow_add(fsw, &req, &error);
	if (fo == NULL) {
		ASSERT(error != 0);
		ASSERT(req.nfr_flow_stats == NULL);
		goto done;
	}

	ASSERT(error == 0);
	ASSERT(req.nfr_nx_port != NEXUS_PORT_ANY);
	ASSERT(!uuid_is_null(fo->fo_key));
	ASSERT(req.nfr_flowadv_idx != FLOWADV_IDX_NONE);
	ASSERT(req.nfr_flow_stats != NULL);
	ASSERT(flow_stats_refcnt(req.nfr_flow_stats) >= 1);

	bzero(&local_endpoint, sizeof(local_endpoint));
	bzero(&remote_endpoint, sizeof(remote_endpoint));

	bcopy((void *)&req.nfr_saddr, (void *)&local_endpoint.u.sin6,
	    sizeof(req.nfr_saddr));
	bcopy((void *)&req.nfr_daddr, (void *)&remote_endpoint.u.sin6,
	    sizeof(req.nfr_daddr));

	assign_message =
	    necp_create_nexus_assign_message(fsw->fsw_nx->nx_uuid,
	    req.nfr_nx_port, fo->fo_key, sizeof(fo->fo_key),
	    &local_endpoint, &remote_endpoint, NULL, req.nfr_flowadv_idx,
	    req.nfr_flow_stats, &assign_message_length);

	if (assign_message != NULL) {
		req.nfr_flow_stats = NULL;
		ASSERT(error == 0);
		*results = assign_message;
		*results_length = assign_message_length;
	} else {
		error = ENOMEM;
	}

done:
#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_FLOW) != 0)) {
		uuid_string_t uuidstr;
		SK_DF(SK_VERB_FLOW, "pid %d connect flow_uuid %s nx_port %d "
		    "(err %d)", pid, sk_uuid_unparse(flow_uuid, uuidstr),
		    (int)req.nfr_nx_port, error);
	}
#endif /* SK_LOG */
	if (error != 0) {
		ASSERT(*results == NULL);
		ASSERT(*results_length == 0);
		if (assign_message != NULL) {
			kfree_data(assign_message, assign_message_length);
			assign_message = NULL;
		}
		if (fo != NULL) {
			req.nfr_pid = pid;
			fsw_flow_del(fsw, &req, TRUE, NULL);
		}
		if (req.nfr_flow_stats != NULL) {
			flow_stats_release(req.nfr_flow_stats);
			req.nfr_flow_stats = NULL;
		}
	}

	return error;
}

static int
fsw_netagent_flow_del(struct nx_flowswitch *fsw, uuid_t flow_uuid, pid_t pid,
    bool nolinger, void *context, void *params)
{
	struct nx_flow_req req;
	int error;

	bzero(&req, sizeof(req));
	uuid_copy(req.nfr_flow_uuid, flow_uuid);
	req.nfr_proc = NULL;
	req.nfr_pid = pid;
	req.nfr_context = context;

	error = fsw_flow_del(fsw, &req, nolinger, params);

#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_FLOW) != 0)) {
		uuid_string_t uuidstr;
		SK_DF(SK_VERB_FLOW, "pid %d flow_uuid %s (err %d)",
		    pid, sk_uuid_unparse(flow_uuid, uuidstr), error);
	}
#endif /* SK_LOG */

	return error;
}

static int
fsw_netagent_event(u_int8_t event, uuid_t flow_uuid, pid_t pid, void *context,
    void *ctx, struct necp_client_agent_parameters *cparams, void **results,
    size_t *results_length)
{
	struct nx_flowswitch *fsw;
	int error = 0;

	ASSERT(!uuid_is_null(flow_uuid));

	fsw = (struct nx_flowswitch *)ctx;
	ASSERT(fsw != NULL);

	switch (event) {
	case NETAGENT_EVENT_NEXUS_FLOW_INSERT:
		/* these are required for this event */
		ASSERT(cparams != NULL);
		ASSERT(results != NULL);
		ASSERT(results_length != NULL);
		*results = NULL;
		*results_length = 0;
		error = fsw_netagent_flow_add(fsw, flow_uuid, pid, context,
		    &cparams->u.nexus_request, results, results_length);
		break;

	case NETAGENT_EVENT_NEXUS_FLOW_REMOVE:
	case NETAGENT_EVENT_NEXUS_FLOW_ABORT:
		/*
		 * A flow can be removed gracefully (FLOW_REMOVE) by
		 * the client, in which case we don't need to have it
		 * linger around to hold the namespace.  If the process
		 * crashed or if it's suspended, then we treat that
		 * as the abort case (FLOW_ABORT) where we'll hold on
		 * to the namespace if needed.
		 */
		error = fsw_netagent_flow_del(fsw, flow_uuid, pid,
		    (event == NETAGENT_EVENT_NEXUS_FLOW_REMOVE), context,
		    cparams);
		break;

	default:
		/* events not handled */
		return 0;
	}

	return error;
}

int
fsw_netagent_register(struct nx_flowswitch *fsw, struct ifnet *ifp)
{
	struct netagent_nexus_agent agent;
	int error = 0;

	_CASSERT(FLOWADV_IDX_NONE == UINT32_MAX);
	_CASSERT(NECP_FLOWADV_IDX_INVALID == FLOWADV_IDX_NONE);

	if (!fsw_netagent) {
		return 0;
	}

	fsw->fsw_agent_session = netagent_create(fsw_netagent_event, fsw);
	if (fsw->fsw_agent_session == NULL) {
		return ENOMEM;
	}

	bzero(&agent, sizeof(agent));
	uuid_generate_random(agent.agent.netagent_uuid);
	uuid_copy(fsw->fsw_agent_uuid, agent.agent.netagent_uuid);
	(void) snprintf(agent.agent.netagent_domain,
	    sizeof(agent.agent.netagent_domain), "%s", "Skywalk");
	(void) snprintf(agent.agent.netagent_type,
	    sizeof(agent.agent.netagent_type), "%s", "FlowSwitch");
	(void) snprintf(agent.agent.netagent_desc,
	    sizeof(agent.agent.netagent_desc), "%s", "Userspace Networking");
	agent.agent.netagent_flags = NETAGENT_FLAG_ACTIVE;
	if (ifnet_needs_fsw_transport_netagent(ifp)) {
		agent.agent.netagent_flags |= (NETAGENT_FLAG_NEXUS_PROVIDER |
		    NETAGENT_FLAG_NEXUS_LISTENER);
	}
	if (ifnet_needs_fsw_ip_netagent(ifp)) {
		ASSERT((sk_features & SK_FEATURE_PROTONS) != 0);
		agent.agent.netagent_flags |= (NETAGENT_FLAG_CUSTOM_IP_NEXUS |
		    NETAGENT_FLAG_NEXUS_LISTENER);
	}
	agent.agent.netagent_data_size = sizeof(struct netagent_nexus);
	agent.nexus_data.frame_type = NETAGENT_NEXUS_FRAME_TYPE_INTERNET;
	agent.nexus_data.endpoint_assignment_type =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_ADDRESS;
	agent.nexus_data.endpoint_request_types[0] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_ADDRESS;
	agent.nexus_data.endpoint_resolution_type_pairs[0] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_HOST;
	agent.nexus_data.endpoint_resolution_type_pairs[1] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_ADDRESS;
	agent.nexus_data.endpoint_resolution_type_pairs[2] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_BONJOUR;
	agent.nexus_data.endpoint_resolution_type_pairs[3] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_HOST;
	agent.nexus_data.endpoint_resolution_type_pairs[4] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_SRV;
	agent.nexus_data.endpoint_resolution_type_pairs[5] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_HOST;
	agent.nexus_data.nexus_max_buf_size =
	    fsw->fsw_nx->nx_prov->nxprov_params->nxp_buf_size;
	agent.nexus_data.nexus_flags |=
	    (NETAGENT_NEXUS_FLAG_SUPPORTS_USER_PACKET_POOL |
	    NETAGENT_NEXUS_FLAG_ASSERT_UNSUPPORTED);

	error = netagent_register(fsw->fsw_agent_session, &agent.agent);
	if (error != 0) {
		goto fail_netagent_register;
	}

	if (ifp->if_bridge != NULL) {
		/* see rdar://107076453 */
		SK_ERR("%s is bridged, not adding netagent",
		    if_name(ifp));
		goto done;
	}
	error = if_add_netagent(ifp, fsw->fsw_agent_uuid);
	if (error != 0) {
		goto fail_netagent_add;
	}
	fsw->fsw_state_flags |= FSW_STATEF_NETAGENT_ADDED;
	if (if_is_fsw_netagent_enabled()) {
		fsw->fsw_state_flags |= FSW_STATEF_NETAGENT_ENABLED;
	}
done:
	return 0;

fail_netagent_add:
	netagent_unregister(fsw->fsw_agent_session);

fail_netagent_register:
	netagent_destroy(fsw->fsw_agent_session);
	fsw->fsw_agent_session = NULL;
	uuid_clear(fsw->fsw_agent_uuid);

	return error;
}

void
fsw_netagent_unregister(struct nx_flowswitch *fsw, struct ifnet *ifp)
{
	if (!uuid_is_null(fsw->fsw_agent_uuid)) {
		if_delete_netagent(ifp, fsw->fsw_agent_uuid);
	}

	if (fsw->fsw_agent_session != NULL) {
		netagent_destroy(fsw->fsw_agent_session);
		fsw->fsw_agent_session = NULL;
		uuid_clear(fsw->fsw_agent_uuid);
	}
}
