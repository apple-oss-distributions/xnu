/*
 * Copyright (c) 2014-2021 Apple Inc. All rights reserved.
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

#include <string.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/kern_control.h>
#include <sys/mbuf.h>
#include <sys/kpi_mbuf.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/kern_event.h>
#include <sys/sysproto.h>
#include <net/network_agent.h>
#include <net/if_var.h>
#include <net/necp.h>
#include <os/log.h>

u_int32_t netagent_debug = LOG_NOTICE; // 0=None, 1=Basic

SYSCTL_NODE(_net, OID_AUTO, netagent, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "NetworkAgent");
SYSCTL_INT(_net_netagent, OID_AUTO, debug, CTLFLAG_LOCKED | CTLFLAG_RW, &netagent_debug, 0, "");

static int netagent_registered_count = 0;
SYSCTL_INT(_net_netagent, OID_AUTO, registered_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &netagent_registered_count, 0, "");

static int netagent_active_count = 0;
SYSCTL_INT(_net_netagent, OID_AUTO, active_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &netagent_active_count, 0, "");

#define NETAGENTLOG(level, format, ...) do {                                             \
    if (level <= netagent_debug) {                                                       \
	if (level == LOG_ERR) {                                                          \
	    os_log_error(OS_LOG_DEFAULT, "%s: " format "\n", __FUNCTION__, __VA_ARGS__); \
	} else {                                                                         \
	    os_log(OS_LOG_DEFAULT, "%s: " format "\n", __FUNCTION__, __VA_ARGS__);       \
	}                                                                                \
    }                                                                                    \
} while (0)

#define NETAGENTLOG0(level, msg) do {                                                    \
    if (level <= netagent_debug) {                                                       \
	        if (level == LOG_ERR) {                                                          \
	    os_log_error(OS_LOG_DEFAULT, "%s: %s\n", __FUNCTION__, msg);                 \
	} else {                                                                         \
	    os_log(OS_LOG_DEFAULT, "%s: %s\n", __FUNCTION__, msg);                       \
	}                                                                                \
    }                                                                                    \
} while (0)

struct netagent_client {
	LIST_ENTRY(netagent_client) client_chain;
	uuid_t client_id;
	uuid_t client_proc_uuid;
	pid_t client_pid;
};

LIST_HEAD(netagent_client_list_s, netagent_client);

struct netagent_token {
	TAILQ_ENTRY(netagent_token) token_chain;
	u_int32_t token_length;
	u_int8_t *token_bytes;
};

TAILQ_HEAD(netagent_token_list_s, netagent_token);

#define NETAGENT_MAX_CLIENT_ERROR_COUNT 32

struct netagent_wrapper {
	LIST_ENTRY(netagent_wrapper) list_chain;
	lck_rw_t agent_lock;
	u_int32_t control_unit;
	netagent_event_f event_handler;
	void *event_context;
	u_int32_t generation;
	u_int64_t use_count;
	u_int64_t need_tokens_event_deadline;
	u_int32_t token_count;
	u_int32_t token_low_water;
	int32_t last_client_error;
	u_int32_t client_error_count;
	u_int8_t __pad_bytes[3];
	struct netagent_token_list_s token_list;
	struct netagent_client_list_s pending_triggers_list;
	struct netagent *netagent;
};

struct netagent_session {
	u_int32_t control_unit; // A control unit of 0 indicates an agent owned by the kernel
	lck_mtx_t session_lock;
	struct netagent_wrapper *wrapper;
	netagent_event_f event_handler;
	void *event_context;
};

typedef enum {
	kNetagentErrorDomainPOSIX                       = 0,
	kNetagentErrorDomainUserDefined         = 1,
} netagent_error_domain_t;

static LIST_HEAD(_netagent_list, netagent_wrapper) shared_netagent_list =
    LIST_HEAD_INITIALIZER(master_netagent_list);

// Protected by netagent_list_lock
static u_int32_t g_next_generation = 1;

static kern_ctl_ref     netagent_kctlref;
static u_int32_t        netagent_family;
static LCK_GRP_DECLARE(netagent_mtx_grp, NETAGENT_CONTROL_NAME);
static LCK_RW_DECLARE(netagent_list_lock, &netagent_mtx_grp);

#define NETAGENT_LIST_LOCK_EXCLUSIVE() lck_rw_lock_exclusive(&netagent_list_lock)
#define NETAGENT_LIST_LOCK_SHARED() lck_rw_lock_shared(&netagent_list_lock)
#define NETAGENT_LIST_UNLOCK() lck_rw_done(&netagent_list_lock)
#define NETAGENT_LIST_ASSERT_LOCKED() LCK_RW_ASSERT(&netagent_list_lock, LCK_RW_ASSERT_HELD)

#define NETAGENT_SESSION_LOCK(session) lck_mtx_lock(&session->session_lock)
#define NETAGENT_SESSION_UNLOCK(session) lck_mtx_unlock(&session->session_lock)

#define NETAGENT_LOCK_EXCLUSIVE(wrapper) lck_rw_lock_exclusive(&wrapper->agent_lock)
#define NETAGENT_LOCK_SHARED(wrapper) lck_rw_lock_shared(&wrapper->agent_lock)
#define NETAGENT_LOCK_SHARED_TO_EXCLUSIVE(wrapper) lck_rw_lock_shared_to_exclusive(&wrapper->agent_lock)
#define NETAGENT_UNLOCK(wrapper) lck_rw_done(&wrapper->agent_lock)
#define NETAGENT_ASSERT_LOCKED(wrapper) LCK_RW_ASSERT(&wrapper->agent_lock, LCK_RW_ASSERT_HELD)

// Locking Notes

// Precedence, where 1 is the first lock that must be taken
// 1. NETAGENT_LIST_LOCK - protects shared_netagent_list
// 2. NETAGENT_SESSION_LOCK - protects the session->wrapper pointer
// 3. NETAGENT_LOCK -> protects values in a wrapper

static errno_t netagent_register_control(void);
static errno_t netagent_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
    void **unitinfo);
static errno_t netagent_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);
static errno_t netagent_ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
    mbuf_t m, int flags);
static void netagent_ctl_rcvd(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int flags);
static errno_t netagent_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
    int opt, void *data, size_t *len);
static errno_t netagent_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
    int opt, void *data, size_t len);

static int netagent_send_ctl_data(u_int32_t control_unit, u_int8_t *buffer, size_t buffer_size);

static struct netagent_session *netagent_create_session(u_int32_t control_unit);
static void netagent_delete_session(struct netagent_session *session);

// Register
static void netagent_handle_register_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset);
static errno_t netagent_handle_register_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length);

// Unregister
static void netagent_handle_unregister_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset);
static errno_t netagent_handle_unregister_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length);

// Update
static void netagent_handle_update_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset);
static errno_t netagent_handle_update_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length);

// Assign nexus
static void netagent_handle_assign_nexus_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset);
static errno_t netagent_handle_assign_nexus_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length);

// Assign group
static errno_t netagent_handle_assign_group_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length);

// Set/get assert count
static errno_t netagent_handle_use_count_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length);
static errno_t netagent_handle_use_count_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length);

// Manage tokens
static errno_t netagent_handle_add_token_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length);
static errno_t netagent_handle_flush_tokens_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length);
static errno_t netagent_handle_token_count_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length);
static errno_t netagent_handle_token_low_water_setopt(struct netagent_session *session, u_int8_t *buffer, size_t buffer_length);
static errno_t netagent_handle_token_low_water_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length);

// Client error
static errno_t netagent_handle_reset_client_error_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length);

static void netagent_handle_get(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset);

// Requires list lock being held
static struct netagent_wrapper *netagent_find_agent_with_uuid_and_lock(uuid_t uuid, bool exclusively, bool ignore_lock);

errno_t
netagent_init(void)
{
	return netagent_register_control();
}

static errno_t
netagent_register_control(void)
{
	struct kern_ctl_reg     kern_ctl;
	errno_t                 result = 0;

	// Find a unique value for our interface family
	result = mbuf_tag_id_find(NETAGENT_CONTROL_NAME, &netagent_family);
	if (result != 0) {
		NETAGENTLOG(LOG_ERR, "mbuf_tag_id_find_internal failed: %d", result);
		return result;
	}

	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, NETAGENT_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED; // Require root
	kern_ctl.ctl_sendsize = 64 * 1024;
	kern_ctl.ctl_recvsize = 64 * 1024;
	kern_ctl.ctl_connect = netagent_ctl_connect;
	kern_ctl.ctl_disconnect = netagent_ctl_disconnect;
	kern_ctl.ctl_send = netagent_ctl_send;
	kern_ctl.ctl_rcvd = netagent_ctl_rcvd;
	kern_ctl.ctl_setopt = netagent_ctl_setopt;
	kern_ctl.ctl_getopt = netagent_ctl_getopt;

	result = ctl_register(&kern_ctl, &netagent_kctlref);
	if (result != 0) {
		NETAGENTLOG(LOG_ERR, "ctl_register failed: %d", result);
		return result;
	}

	return 0;
}

static errno_t
netagent_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
#pragma unused(kctlref)
	*unitinfo = netagent_create_session(sac->sc_unit);
	if (*unitinfo == NULL) {
		// Could not allocate session
		return ENOBUFS;
	}

	return 0;
}

static errno_t
netagent_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
#pragma unused(kctlref, unit)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	if (session != NULL) {
		netagent_delete_session(session);
	}

	return 0;
}

// Kernel events
static void
netagent_post_event(uuid_t agent_uuid, u_int32_t event_code, bool update_necp, bool should_update_immediately)
{
	if (update_necp) {
		necp_update_all_clients_immediately_if_needed(should_update_immediately);
	}

	struct kev_msg ev_msg;
	memset(&ev_msg, 0, sizeof(ev_msg));

	struct kev_netagent_data event_data;

	ev_msg.vendor_code      = KEV_VENDOR_APPLE;
	ev_msg.kev_class        = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass     = KEV_NETAGENT_SUBCLASS;
	ev_msg.event_code       = event_code;

	uuid_copy(event_data.netagent_uuid, agent_uuid);
	ev_msg.dv[0].data_ptr    = &event_data;
	ev_msg.dv[0].data_length = sizeof(event_data);

	kev_post_msg(&ev_msg);
}

// Message handling
static u_int8_t *
netagent_buffer_write_message_header(u_int8_t *buffer, u_int8_t message_type, u_int8_t flags,
    u_int32_t message_id, u_int32_t error, size_t payload_length)
{
	memset(buffer, 0, sizeof(struct netagent_message_header));
	((struct netagent_message_header *)(void *)buffer)->message_type = message_type;
	((struct netagent_message_header *)(void *)buffer)->message_flags = flags;
	((struct netagent_message_header *)(void *)buffer)->message_id = message_id;
	((struct netagent_message_header *)(void *)buffer)->message_error = error;
	((struct netagent_message_header *)(void *)buffer)->message_payload_length = (u_int32_t)payload_length;
	return buffer + sizeof(struct netagent_message_header);
}

static int
netagent_send_ctl_data(u_int32_t control_unit, u_int8_t *buffer, size_t buffer_size)
{
	if (netagent_kctlref == NULL || control_unit == 0 || buffer == NULL || buffer_size == 0) {
		return EINVAL;
	}

	return ctl_enqueuedata(netagent_kctlref, control_unit, buffer, buffer_size, CTL_DATA_EOR);
}

static int
netagent_send_trigger(struct netagent_wrapper *wrapper, struct proc *p, u_int32_t flags, u_int8_t trigger_type)
{
	int error = 0;
	struct netagent_trigger_message *trigger_message = NULL;
	u_int8_t *trigger = NULL;
	size_t trigger_size = sizeof(struct netagent_message_header) + sizeof(struct netagent_trigger_message);

	trigger = (u_int8_t *)kalloc_data(trigger_size, Z_WAITOK);
	if (trigger == NULL) {
		return ENOMEM;
	}

	(void)netagent_buffer_write_message_header(trigger, trigger_type, 0, 0, 0, sizeof(struct netagent_trigger_message));

	trigger_message = (struct netagent_trigger_message *)(void *)(trigger + sizeof(struct netagent_message_header));
	trigger_message->trigger_flags = flags;
	if (p != NULL) {
		trigger_message->trigger_pid = proc_pid(p);
		proc_getexecutableuuid(p, trigger_message->trigger_proc_uuid, sizeof(trigger_message->trigger_proc_uuid));
	} else {
		trigger_message->trigger_pid = 0;
		uuid_clear(trigger_message->trigger_proc_uuid);
	}

	if ((error = netagent_send_ctl_data(wrapper->control_unit, trigger, trigger_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send trigger message on control unit %d", wrapper->control_unit);
	}

	kfree_data(trigger, trigger_size);
	return error;
}

static int
netagent_send_client_message(struct netagent_wrapper *wrapper, uuid_t client_id, u_int8_t message_type)
{
	int error = 0;
	struct netagent_client_message *client_message = NULL;
	u_int8_t *message = NULL;
	size_t message_size = sizeof(struct netagent_message_header) + sizeof(struct netagent_client_message);

	message = (u_int8_t *)kalloc_data(message_size, Z_WAITOK);
	if (message == NULL) {
		return ENOMEM;
	}

	(void)netagent_buffer_write_message_header(message, message_type, 0, 0, 0, sizeof(struct netagent_client_message));

	client_message = (struct netagent_client_message *)(void *)(message + sizeof(struct netagent_message_header));
	uuid_copy(client_message->client_id, client_id);

	if ((error = netagent_send_ctl_data(wrapper->control_unit, message, message_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send client message %d on control unit %d", message_type, wrapper->control_unit);
	}

	kfree_data(message, message_size);
	return error;
}

static int
netagent_send_error_message(struct netagent_wrapper *wrapper, uuid_t client_id, u_int8_t message_type, int32_t error_code)
{
	int error = 0;
	struct netagent_client_error_message *client_message = NULL;
	u_int8_t *message = NULL;
	size_t message_size = sizeof(struct netagent_message_header) + sizeof(struct netagent_client_error_message);

	message = (u_int8_t *)kalloc_data(message_size, Z_WAITOK);
	if (message == NULL) {
		return ENOMEM;
	}

	(void)netagent_buffer_write_message_header(message, message_type, 0, 0, 0, sizeof(struct netagent_client_error_message));

	client_message = (struct netagent_client_error_message *)(void *)(message + sizeof(struct netagent_message_header));
	uuid_copy(client_message->client_id, client_id);
	client_message->error_code = error_code;

	if ((error = netagent_send_ctl_data(wrapper->control_unit, message, message_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send client message %d on control unit %d", message_type, wrapper->control_unit);
	}

	kfree_data(message, message_size);
	return error;
}

static int
netagent_send_group_message(struct netagent_wrapper *wrapper, uuid_t client_id, u_int8_t message_type, struct necp_client_group_members *group_members)
{
	int error = 0;
	struct netagent_client_group_message *client_message = NULL;
	u_int8_t *message = NULL;
	size_t message_size = sizeof(struct netagent_message_header) + sizeof(struct netagent_client_group_message) + group_members->group_members_length;

	message = (u_int8_t *)kalloc_data(message_size, Z_WAITOK);
	if (message == NULL) {
		return ENOMEM;
	}

	(void)netagent_buffer_write_message_header(message, message_type, 0, 0, 0, sizeof(struct netagent_client_group_message) + group_members->group_members_length);

	client_message = (struct netagent_client_group_message *)(void *)(message + sizeof(struct netagent_message_header));
	uuid_copy(client_message->client_id, client_id);
	memcpy(client_message->group_members, group_members->group_members, group_members->group_members_length);

	if ((error = netagent_send_ctl_data(wrapper->control_unit, message, message_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send client group message %d on control unit %d", message_type, wrapper->control_unit);
	}

	kfree_data(message, message_size);
	return error;
}

static int
netagent_send_tokens_needed(struct netagent_wrapper *wrapper)
{
	const u_int8_t message_type = NETAGENT_MESSAGE_TYPE_TOKENS_NEEDED;
	int error = 0;
	u_int8_t *message = NULL;
	size_t message_size = sizeof(struct netagent_message_header);

	message = (u_int8_t *)kalloc_data(message_size, Z_WAITOK);
	if (message == NULL) {
		return ENOMEM;
	}

	(void)netagent_buffer_write_message_header(message, message_type, 0, 0, 0, 0);

	if ((error = netagent_send_ctl_data(wrapper->control_unit, message, message_size))) {
		NETAGENTLOG(LOG_ERR, "Failed to send client tokens needed message on control unit %d", wrapper->control_unit);
	}

	kfree_data(message, message_size);
	return error;
}

static int
netagent_send_success_response(struct netagent_session *session, u_int8_t message_type, u_int32_t message_id)
{
	int error = 0;
	u_int8_t *response = NULL;
	size_t response_size = sizeof(struct netagent_message_header);
	response = (u_int8_t *)kalloc_data(response_size, Z_WAITOK);
	if (response == NULL) {
		return ENOMEM;
	}
	(void)netagent_buffer_write_message_header(response, message_type, NETAGENT_MESSAGE_FLAGS_RESPONSE, message_id, 0, 0);

	if ((error = netagent_send_ctl_data(session->control_unit, response, response_size))) {
		NETAGENTLOG0(LOG_ERR, "Failed to send response");
	}

	kfree_data(response, response_size);
	return error;
}

static errno_t
netagent_send_error_response(struct netagent_session *session, u_int8_t message_type,
    u_int32_t message_id, u_int32_t error_code)
{
	int error = 0;
	u_int8_t *response = NULL;
	size_t response_size = sizeof(struct netagent_message_header);

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Got a NULL session");
		return EINVAL;
	}

	response = (u_int8_t *)kalloc_data(response_size, Z_WAITOK);
	if (response == NULL) {
		return ENOMEM;
	}
	(void)netagent_buffer_write_message_header(response, message_type, NETAGENT_MESSAGE_FLAGS_RESPONSE,
	    message_id, error_code, 0);

	if ((error = netagent_send_ctl_data(session->control_unit, response, response_size))) {
		NETAGENTLOG0(LOG_ERR, "Failed to send response");
	}

	kfree_data(response, response_size);
	return error;
}

static errno_t
netagent_ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t packet, int flags)
{
#pragma unused(kctlref, unit, flags)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	struct netagent_message_header header;
	int error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Got a NULL session");
		error = EINVAL;
		goto done;
	}

	if (mbuf_pkthdr_len(packet) < sizeof(header)) {
		NETAGENTLOG(LOG_ERR, "Got a bad packet, length (%lu) < sizeof header (%lu)",
		    mbuf_pkthdr_len(packet), sizeof(header));
		error = EINVAL;
		goto done;
	}

	error = mbuf_copydata(packet, 0, sizeof(header), &header);
	if (error) {
		NETAGENTLOG(LOG_ERR, "mbuf_copydata failed for the header: %d", error);
		error = ENOBUFS;
		goto done;
	}

	switch (header.message_type) {
	case NETAGENT_MESSAGE_TYPE_REGISTER: {
		netagent_handle_register_message(session, header.message_id, header.message_payload_length,
		    packet, sizeof(header));
		break;
	}
	case NETAGENT_MESSAGE_TYPE_UNREGISTER: {
		netagent_handle_unregister_message(session, header.message_id, header.message_payload_length,
		    packet, sizeof(header));
		break;
	}
	case NETAGENT_MESSAGE_TYPE_UPDATE: {
		netagent_handle_update_message(session, header.message_id, header.message_payload_length,
		    packet, sizeof(header));
		break;
	}
	case NETAGENT_MESSAGE_TYPE_GET: {
		netagent_handle_get(session, header.message_id, header.message_payload_length,
		    packet, sizeof(header));
		break;
	}
	case NETAGENT_MESSAGE_TYPE_ASSERT: {
		NETAGENTLOG0(LOG_ERR, "NETAGENT_MESSAGE_TYPE_ASSERT no longer supported");
		break;
	}
	case NETAGENT_MESSAGE_TYPE_UNASSERT: {
		NETAGENTLOG0(LOG_ERR, "NETAGENT_MESSAGE_TYPE_UNASSERT no longer supported");
		break;
	}
	case NETAGENT_MESSAGE_TYPE_ASSIGN_NEXUS: {
		netagent_handle_assign_nexus_message(session, header.message_id, header.message_payload_length,
		    packet, sizeof(header));
		break;
	}
	default: {
		NETAGENTLOG(LOG_ERR, "Received unknown message type %d", header.message_type);
		netagent_send_error_response(session, header.message_type, header.message_id,
		    NETAGENT_MESSAGE_ERROR_UNKNOWN_TYPE);
		break;
	}
	}

done:
	mbuf_freem(packet);
	return error;
}

static void
netagent_ctl_rcvd(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int flags)
{
#pragma unused(kctlref, unit, unitinfo, flags)
	return;
}

static errno_t
netagent_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt,
    void *data, size_t *len)
{
#pragma unused(kctlref, unit)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	errno_t error;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Received a NULL session");
		error = EINVAL;
		goto done;
	}

	switch (opt) {
	case NETAGENT_OPTION_TYPE_USE_COUNT: {
		NETAGENTLOG0(LOG_DEBUG, "Request to get use count");
		error = netagent_handle_use_count_getopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_TOKEN_COUNT: {
		NETAGENTLOG0(LOG_DEBUG, "Request to get token count");
		error = netagent_handle_token_count_getopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_TOKEN_LOW_WATER: {
		NETAGENTLOG0(LOG_DEBUG, "Request to get token low water mark");
		error = netagent_handle_token_low_water_getopt(session, data, len);
		break;
	}
	default:
		NETAGENTLOG0(LOG_ERR, "Received unknown option");
		error = ENOPROTOOPT;
		break;
	}

done:
	return error;
}

static errno_t
netagent_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt,
    void *data, size_t len)
{
#pragma unused(kctlref, unit)
	struct netagent_session *session = (struct netagent_session *)unitinfo;
	errno_t error;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Received a NULL session");
		error = EINVAL;
		goto done;
	}

	switch (opt) {
	case NETAGENT_OPTION_TYPE_REGISTER: {
		NETAGENTLOG0(LOG_DEBUG, "Request for registration");
		error = netagent_handle_register_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_UPDATE: {
		NETAGENTLOG0(LOG_DEBUG, "Request for update");
		error = netagent_handle_update_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_UNREGISTER: {
		NETAGENTLOG0(LOG_DEBUG, "Request for unregistration");
		error = netagent_handle_unregister_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_ASSIGN_NEXUS: {
		NETAGENTLOG0(LOG_DEBUG, "Request for assigning nexus");
		error = netagent_handle_assign_nexus_setopt(session, data, len);
		break;
	}
	case NETAGENT_MESSAGE_TYPE_ASSIGN_GROUP_MEMBERS: {
		NETAGENTLOG0(LOG_DEBUG, "Request for assigning group members");
		error = netagent_handle_assign_group_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_USE_COUNT: {
		NETAGENTLOG0(LOG_DEBUG, "Request to set use count");
		error = netagent_handle_use_count_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_ADD_TOKEN: {
		NETAGENTLOG0(LOG_DEBUG, "Request to add a token");
		error = netagent_handle_add_token_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_FLUSH_TOKENS: {
		NETAGENTLOG0(LOG_DEBUG, "Request to flush tokens");
		error = netagent_handle_flush_tokens_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_TOKEN_LOW_WATER: {
		NETAGENTLOG0(LOG_DEBUG, "Request to set token low water mark");
		error = netagent_handle_token_low_water_setopt(session, data, len);
		break;
	}
	case NETAGENT_OPTION_TYPE_RESET_CLIENT_ERROR: {
		NETAGENTLOG0(LOG_DEBUG, "Request to reset client error");
		error = netagent_handle_reset_client_error_setopt(session, data, len);
		break;
	}
	default:
		NETAGENTLOG0(LOG_ERR, "Received unknown option");
		error = ENOPROTOOPT;
		break;
	}

done:
	return error;
}

// Session Management
static struct netagent_session *
netagent_create_session(u_int32_t control_unit)
{
	struct netagent_session *new_session = NULL;

	new_session = kalloc_type(struct netagent_session,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	NETAGENTLOG(LOG_DEBUG, "Create agent session, control unit %d", control_unit);
	new_session->control_unit = control_unit;
	lck_mtx_init(&new_session->session_lock, &netagent_mtx_grp, LCK_ATTR_NULL);

	return new_session;
}

netagent_session_t
netagent_create(netagent_event_f event_handler, void *context)
{
	struct netagent_session *session = netagent_create_session(0);
	if (session == NULL) {
		return NULL;
	}

	session->event_handler = event_handler;
	session->event_context = context;
	return session;
}

static void
netagent_token_free(struct netagent_token *token)
{
	kfree_data(token->token_bytes, token->token_length);
	kfree_type(struct netagent_token, token);
}

static struct netagent_wrapper *
netagent_alloc_wrapper_memory(uint32_t data_size)
{
	struct netagent_wrapper *new_wrapper;

	new_wrapper = kalloc_type(struct netagent_wrapper,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	new_wrapper->netagent = kalloc_data(sizeof(struct netagent) + data_size,
	    Z_WAITOK | Z_NOFAIL);

	lck_rw_init(&new_wrapper->agent_lock, &netagent_mtx_grp, LCK_ATTR_NULL);

	return new_wrapper;
}

static void
netagent_free_wrapper_memory(struct netagent_wrapper *wrapper)
{
	// Before destroying the lock, take the lock exclusively and then
	// drop it again. This ensures that no other thread was holding
	// onto the lock at the time of destroying it.
	// This can happen in netagent_client_message_with_params due
	// to the fact that the wrapper lock needs to be held during the
	// event callout, while the list lock has been released. Taking
	// this lock here ensures that any such remaining thread completes
	// before this object is released. Since the wrapper object has
	// already been removed from any and all lists by this point,
	// there isn't any way for a new thread to start referencing it.
	NETAGENT_LOCK_EXCLUSIVE(wrapper);
	NETAGENT_UNLOCK(wrapper);
	lck_rw_destroy(&wrapper->agent_lock, &netagent_mtx_grp);

	kfree_data(wrapper->netagent, sizeof(struct netagent) +
	    wrapper->netagent->netagent_data_size);
	kfree_type(struct netagent_wrapper, wrapper);
}

static void
netagent_free_wrapper(struct netagent_wrapper *wrapper)
{
	// Free any leftover tokens
	struct netagent_token *search_token = NULL;
	struct netagent_token *temp_token = NULL;
	TAILQ_FOREACH_SAFE(search_token, &wrapper->token_list, token_chain, temp_token) {
		TAILQ_REMOVE(&wrapper->token_list, search_token, token_chain);
		netagent_token_free(search_token);
	}

	// Free any pending client triggers
	struct netagent_client *search_client = NULL;
	struct netagent_client *temp_client = NULL;
	LIST_FOREACH_SAFE(search_client, &wrapper->pending_triggers_list, client_chain, temp_client) {
		LIST_REMOVE(search_client, client_chain);
		kfree_type(struct netagent_client, search_client);
	}

	// Free wrapper itself
	netagent_free_wrapper_memory(wrapper);
}

static void
netagent_unregister_session_wrapper(struct netagent_session *session)
{
	bool unregistered = FALSE;
	uuid_t unregistered_uuid;
	struct netagent_wrapper *wrapper = NULL;
	NETAGENT_LIST_LOCK_EXCLUSIVE();
	if (session != NULL) {
		NETAGENT_SESSION_LOCK(session);
		wrapper = session->wrapper;
		if (wrapper != NULL) {
			if (netagent_registered_count > 0) {
				netagent_registered_count--;
			}
			if ((session->wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) &&
			    netagent_active_count > 0) {
				netagent_active_count--;
			}

			LIST_REMOVE(wrapper, list_chain);

			unregistered = TRUE;
			uuid_copy(unregistered_uuid, session->wrapper->netagent->netagent_uuid);

			netagent_free_wrapper(session->wrapper);
			session->wrapper = NULL;
			NETAGENTLOG0(LOG_DEBUG, "Unregistered agent");
		}
		NETAGENT_SESSION_UNLOCK(session);
	}
	NETAGENT_LIST_UNLOCK();

	if (unregistered) {
		ifnet_clear_netagent(unregistered_uuid);
		netagent_post_event(unregistered_uuid, KEV_NETAGENT_UNREGISTERED, TRUE, false);
	}
}

static void
netagent_delete_session(struct netagent_session *session)
{
	if (session != NULL) {
		netagent_unregister_session_wrapper(session);
		lck_mtx_destroy(&session->session_lock, &netagent_mtx_grp);
		kfree_type(struct netagent_session, session);
	}
}

void
netagent_destroy(netagent_session_t session)
{
	return netagent_delete_session((struct netagent_session *)session);
}

static size_t
netagent_packet_get_netagent_data_size(mbuf_t packet, size_t offset, int *err)
{
	int error = 0;

	struct netagent netagent_peek;
	memset(&netagent_peek, 0, sizeof(netagent_peek));

	*err = 0;

	error = mbuf_copydata(packet, offset, sizeof(netagent_peek), &netagent_peek);
	if (error) {
		*err = ENOENT;
		return 0;
	}

	return netagent_peek.netagent_data_size;
}

static errno_t
netagent_handle_register_inner(struct netagent_session *session, struct netagent_wrapper *new_wrapper)
{
	NETAGENT_LIST_LOCK_EXCLUSIVE();

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper != NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENT_LIST_UNLOCK();
		return EINVAL;
	}

	new_wrapper->control_unit = session->control_unit;
	new_wrapper->event_handler = session->event_handler;
	new_wrapper->event_context = session->event_context;
	new_wrapper->generation = g_next_generation++;

	session->wrapper = new_wrapper;
	LIST_INSERT_HEAD(&shared_netagent_list, new_wrapper, list_chain);
	TAILQ_INIT(&new_wrapper->token_list);
	LIST_INIT(&new_wrapper->pending_triggers_list);

	new_wrapper->netagent->netagent_flags |= NETAGENT_FLAG_REGISTERED;
	netagent_registered_count++;
	if (new_wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) {
		netagent_active_count++;
	}

	NETAGENT_SESSION_UNLOCK(session);
	NETAGENT_LIST_UNLOCK();
	return 0;
}

errno_t
netagent_register(netagent_session_t _session, struct netagent *agent)
{
	struct netagent_wrapper *new_wrapper = NULL;
	uuid_t registered_uuid;

	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot register agent on NULL session");
		return EINVAL;
	}

	if (agent == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot register NULL agent");
		return EINVAL;
	}

	size_t data_size = agent->netagent_data_size;
	if (data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Register message size could not be read, data_size %zu",
		    data_size);
		return EINVAL;
	}

	new_wrapper = netagent_alloc_wrapper_memory(data_size);

	__nochk_memcpy(new_wrapper->netagent, agent, sizeof(struct netagent) + data_size);

	uuid_copy(registered_uuid, new_wrapper->netagent->netagent_uuid);

	errno_t error = netagent_handle_register_inner(session, new_wrapper);
	if (error != 0) {
		netagent_free_wrapper_memory(new_wrapper);
		return error;
	}

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_post_event(registered_uuid, KEV_NETAGENT_REGISTERED, TRUE, false);

	return 0;
}

static errno_t
netagent_handle_register_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length)
{
	struct netagent_wrapper *new_wrapper = NULL;
	errno_t response_error = 0;
	struct netagent *register_netagent = (struct netagent *)(void *)payload;
	uuid_t registered_uuid;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = EINVAL;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Register message size too small for agent: (%zu < %zu)",
		    payload_length, sizeof(struct netagent));
		response_error = EINVAL;
		goto done;
	}

	size_t data_size = register_netagent->netagent_data_size;
	if (data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Register message size could not be read, data_size %zu", data_size);
		response_error = EINVAL;
		goto done;
	}

	if (payload_length != (sizeof(struct netagent) + data_size)) {
		NETAGENTLOG(LOG_ERR, "Mismatch between data size and payload length (%lu != %zu)", (sizeof(struct netagent) + data_size), payload_length);
		response_error = EINVAL;
		goto done;
	}

	new_wrapper = netagent_alloc_wrapper_memory(data_size);

	__nochk_memcpy(new_wrapper->netagent, register_netagent, sizeof(struct netagent) + data_size);

	uuid_copy(registered_uuid, new_wrapper->netagent->netagent_uuid);

	response_error = netagent_handle_register_inner(session, new_wrapper);
	if (response_error != 0) {
		netagent_free_wrapper_memory(new_wrapper);
		goto done;
	}

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_post_event(registered_uuid, KEV_NETAGENT_REGISTERED, TRUE, false);

done:
	return response_error;
}

static void
netagent_handle_register_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset)
{
	errno_t error;
	struct netagent_wrapper *new_wrapper = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	uuid_t registered_uuid;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Register message size too small for agent: (%zu < %zu)",
		    payload_length, sizeof(struct netagent));
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	size_t data_size = netagent_packet_get_netagent_data_size(packet, offset, &error);
	if (error || data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Register message size could not be read, error %d data_size %zu",
		    error, data_size);
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	new_wrapper = netagent_alloc_wrapper_memory(data_size);

	error = mbuf_copydata(packet, offset, sizeof(struct netagent) + data_size,
	    new_wrapper->netagent);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read data into agent structure: %d", error);
		netagent_free_wrapper_memory(new_wrapper);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	uuid_copy(registered_uuid, new_wrapper->netagent->netagent_uuid);

	error = netagent_handle_register_inner(session, new_wrapper);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to register agent: %d", error);
		netagent_free_wrapper_memory(new_wrapper);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	NETAGENTLOG0(LOG_DEBUG, "Registered new agent");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_REGISTER, message_id);
	netagent_post_event(registered_uuid, KEV_NETAGENT_REGISTERED, TRUE, false);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_REGISTER, message_id, response_error);
}

errno_t
netagent_unregister(netagent_session_t _session)
{
	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot unregister NULL session");
		return EINVAL;
	}

	netagent_unregister_session_wrapper(session);
	return 0;
}

static errno_t
netagent_handle_unregister_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length)
{
#pragma unused(payload, payload_length)
	errno_t response_error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = EINVAL;
		goto done;
	}

	netagent_unregister_session_wrapper(session);

done:
	return response_error;
}

static void
netagent_handle_unregister_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset)
{
#pragma unused(payload_length, packet, offset)
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	netagent_unregister_session_wrapper(session);

	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_UNREGISTER, message_id);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_UNREGISTER, message_id, response_error);
}

static void
netagent_send_cellular_failed_event(struct netagent_wrapper *wrapper,
    pid_t pid, uuid_t proc_uuid)
{
	if (strncmp(wrapper->netagent->netagent_domain, "Cellular", NETAGENT_DOMAINSIZE) != 0) {
		return;
	}

	struct kev_netpolicy_ifdenied ev_ifdenied;

	bzero(&ev_ifdenied, sizeof(ev_ifdenied));

	ev_ifdenied.ev_data.epid = (u_int64_t)pid;
	uuid_copy(ev_ifdenied.ev_data.euuid, proc_uuid);
	ev_ifdenied.ev_if_functional_type = IFRTYPE_FUNCTIONAL_CELLULAR;

	netpolicy_post_msg(KEV_NETPOLICY_IFFAILED, &ev_ifdenied.ev_data, sizeof(ev_ifdenied));
}

static errno_t
netagent_handle_update_inner(struct netagent_session *session, struct netagent_wrapper *new_wrapper,
    size_t data_size, u_int8_t *agent_changed, netagent_error_domain_t error_domain)
{
	errno_t response_error = 0;

	if (agent_changed == NULL) {
		NETAGENTLOG0(LOG_ERR, "Invalid argument: agent_changed");
		return EINVAL;
	}

	NETAGENT_LIST_LOCK_EXCLUSIVE();

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENT_LIST_UNLOCK();
		response_error = ENOENT;
		return response_error;
	}

	NETAGENT_LOCK_EXCLUSIVE(session->wrapper);

	if (uuid_compare(session->wrapper->netagent->netagent_uuid, new_wrapper->netagent->netagent_uuid) != 0 ||
	    memcmp(&session->wrapper->netagent->netagent_domain, &new_wrapper->netagent->netagent_domain,
	    sizeof(new_wrapper->netagent->netagent_domain)) != 0 ||
	    memcmp(&session->wrapper->netagent->netagent_type, &new_wrapper->netagent->netagent_type,
	    sizeof(new_wrapper->netagent->netagent_type)) != 0) {
		NETAGENT_UNLOCK(session->wrapper);
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENT_LIST_UNLOCK();
		NETAGENTLOG0(LOG_ERR, "Basic agent parameters do not match, cannot update");
		if (error_domain == kNetagentErrorDomainPOSIX) {
			response_error = EINVAL;
		} else if (error_domain == kNetagentErrorDomainUserDefined) {
			response_error = NETAGENT_MESSAGE_ERROR_CANNOT_UPDATE;
		}
		return response_error;
	}

	new_wrapper->netagent->netagent_flags |= NETAGENT_FLAG_REGISTERED;
	if (session->wrapper->netagent->netagent_data_size == new_wrapper->netagent->netagent_data_size &&
	    memcmp(session->wrapper->netagent, new_wrapper->netagent, sizeof(struct netagent) + data_size) == 0) {
		// Agent is exactly identical, don't increment the generation count

		// Make a copy of the list of pending clients, and clear the current list
		struct netagent_client_list_s pending_triggers_list_copy;
		LIST_INIT(&pending_triggers_list_copy);
		struct netagent_client *search_client = NULL;
		struct netagent_client *temp_client = NULL;
		LIST_FOREACH_SAFE(search_client, &session->wrapper->pending_triggers_list, client_chain, temp_client) {
			LIST_REMOVE(search_client, client_chain);
			LIST_INSERT_HEAD(&pending_triggers_list_copy, search_client, client_chain);
		}
		NETAGENT_UNLOCK(session->wrapper);
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENT_LIST_UNLOCK();

		// Update pending client triggers without holding a lock
		search_client = NULL;
		temp_client = NULL;
		LIST_FOREACH_SAFE(search_client, &pending_triggers_list_copy, client_chain, temp_client) {
			necp_force_update_client(search_client->client_id, session->wrapper->netagent->netagent_uuid, session->wrapper->generation);
			netagent_send_cellular_failed_event(new_wrapper, search_client->client_pid, search_client->client_proc_uuid);
			LIST_REMOVE(search_client, client_chain);
			kfree_type(struct netagent_client, search_client);
		}
		NETAGENTLOG0(LOG_DEBUG, "Updated agent (no changes)");
		*agent_changed = FALSE;
		return response_error;
	}

	new_wrapper->generation = g_next_generation++;
	new_wrapper->use_count = session->wrapper->use_count;

	TAILQ_INIT(&new_wrapper->token_list);
	TAILQ_CONCAT(&new_wrapper->token_list, &session->wrapper->token_list, token_chain);
	new_wrapper->token_count = session->wrapper->token_count;
	new_wrapper->token_low_water = session->wrapper->token_low_water;
	new_wrapper->last_client_error = session->wrapper->last_client_error;
	new_wrapper->client_error_count = session->wrapper->client_error_count;

	if ((new_wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) &&
	    !(session->wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		netagent_active_count++;
	} else if (!(new_wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) &&
	    (session->wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) &&
	    netagent_active_count > 0) {
		netagent_active_count--;
	}

	LIST_REMOVE(session->wrapper, list_chain);
	NETAGENT_UNLOCK(session->wrapper);
	netagent_free_wrapper(session->wrapper);
	session->wrapper = new_wrapper;
	new_wrapper->control_unit = session->control_unit;
	new_wrapper->event_handler = session->event_handler;
	new_wrapper->event_context = session->event_context;
	LIST_INSERT_HEAD(&shared_netagent_list, new_wrapper, list_chain);
	LIST_INIT(&new_wrapper->pending_triggers_list);

	NETAGENT_SESSION_UNLOCK(session);
	NETAGENT_LIST_UNLOCK();

	NETAGENTLOG0(LOG_DEBUG, "Updated agent");
	*agent_changed = TRUE;

	return response_error;
}

errno_t
netagent_update(netagent_session_t _session, struct netagent *agent)
{
	u_int8_t agent_changed;
	struct netagent_wrapper *new_wrapper = NULL;
	bool should_update_immediately;
	uuid_t updated_uuid;

	struct netagent_session *session = (struct netagent_session *)_session;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot update agent on NULL session");
		return EINVAL;
	}

	if (agent == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot register NULL agent");
		return EINVAL;
	}

	size_t data_size = agent->netagent_data_size;
	if (data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Update message size (%zu > %u) too large", data_size, NETAGENT_MAX_DATA_SIZE);
		return EINVAL;
	}

	new_wrapper = netagent_alloc_wrapper_memory(data_size);

	__nochk_memcpy(new_wrapper->netagent, agent, sizeof(struct netagent) + data_size);

	uuid_copy(updated_uuid, new_wrapper->netagent->netagent_uuid);
	should_update_immediately = (NETAGENT_FLAG_UPDATE_IMMEDIATELY == (new_wrapper->netagent->netagent_flags & NETAGENT_FLAG_UPDATE_IMMEDIATELY));

	errno_t error = netagent_handle_update_inner(session, new_wrapper, data_size, &agent_changed, kNetagentErrorDomainPOSIX);
	if (error == 0) {
		netagent_post_event(updated_uuid, KEV_NETAGENT_UPDATED, agent_changed, should_update_immediately);
		if (agent_changed == FALSE) {
			// The session wrapper does not need the "new_wrapper" as nothing changed
			netagent_free_wrapper_memory(new_wrapper);
		}
	} else {
		netagent_free_wrapper_memory(new_wrapper);
		return error;
	}

	return 0;
}

static errno_t
netagent_handle_update_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length)
{
	struct netagent_wrapper *new_wrapper = NULL;
	errno_t response_error = 0;
	struct netagent *update_netagent = (struct netagent *)(void *)payload;
	u_int8_t agent_changed;
	bool should_update_immediately;
	uuid_t updated_uuid;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = EINVAL;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Update message size too small for agent: (%zu < %zu)",
		    payload_length, sizeof(struct netagent));
		response_error = EINVAL;
		goto done;
	}

	size_t data_size = update_netagent->netagent_data_size;
	if (data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Update message size (%zu > %u) too large", data_size, NETAGENT_MAX_DATA_SIZE);
		response_error = EINVAL;
		goto done;
	}

	if (payload_length != (sizeof(struct netagent) + data_size)) {
		NETAGENTLOG(LOG_ERR, "Mismatch between data size and payload length (%lu != %zu)", (sizeof(struct netagent) + data_size), payload_length);
		response_error = EINVAL;
		goto done;
	}

	new_wrapper = netagent_alloc_wrapper_memory(data_size);

	__nochk_memcpy(new_wrapper->netagent, update_netagent, sizeof(struct netagent) + data_size);

	uuid_copy(updated_uuid, new_wrapper->netagent->netagent_uuid);
	should_update_immediately = (NETAGENT_FLAG_UPDATE_IMMEDIATELY == (new_wrapper->netagent->netagent_flags & NETAGENT_FLAG_UPDATE_IMMEDIATELY));

	response_error = netagent_handle_update_inner(session, new_wrapper, data_size, &agent_changed, kNetagentErrorDomainPOSIX);
	if (response_error == 0) {
		netagent_post_event(updated_uuid, KEV_NETAGENT_UPDATED, agent_changed, should_update_immediately);
		if (agent_changed == FALSE) {
			// The session wrapper does not need the "new_wrapper" as nothing changed
			netagent_free_wrapper_memory(new_wrapper);
		}
	} else {
		netagent_free_wrapper_memory(new_wrapper);
	}

done:
	return response_error;
}

static void
netagent_handle_update_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset)
{
	int error;
	struct netagent_wrapper *new_wrapper = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	u_int8_t agent_changed;
	uuid_t updated_uuid;
	bool should_update_immediately;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	if (payload_length < sizeof(struct netagent)) {
		NETAGENTLOG(LOG_ERR, "Update message size too small for agent: (%zu < %zu)",
		    payload_length, sizeof(struct netagent));
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	size_t data_size = netagent_packet_get_netagent_data_size(packet, offset, &error);
	if (error || data_size > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Update message size could not be read, error %d data_size %zu",
		    error, data_size);
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	new_wrapper = netagent_alloc_wrapper_memory(data_size);

	error = mbuf_copydata(packet, offset, sizeof(struct netagent) + data_size, new_wrapper->netagent);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read data into agent structure: %d", error);
		netagent_free_wrapper_memory(new_wrapper);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	uuid_copy(updated_uuid, new_wrapper->netagent->netagent_uuid);
	should_update_immediately = (NETAGENT_FLAG_UPDATE_IMMEDIATELY == (new_wrapper->netagent->netagent_flags & NETAGENT_FLAG_UPDATE_IMMEDIATELY));

	response_error = (u_int32_t)netagent_handle_update_inner(session, new_wrapper, data_size, &agent_changed, kNetagentErrorDomainUserDefined);
	if (response_error != 0) {
		if (response_error == ENOENT) {
			response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		}
		netagent_free_wrapper_memory(new_wrapper);
		goto fail;
	}

	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_UPDATE, message_id);

	netagent_post_event(updated_uuid, KEV_NETAGENT_UPDATED, agent_changed, should_update_immediately);

	if (agent_changed == FALSE) {
		// The session wrapper does not need the "new_wrapper" as nothing changed
		netagent_free_wrapper_memory(new_wrapper);
	}

	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_UPDATE, message_id, response_error);
}

static void
netagent_handle_get(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset)
{
#pragma unused(payload_length, packet, offset)
	u_int8_t *response = NULL;
	u_int8_t *cursor = NULL;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}

	NETAGENT_LOCK_SHARED(session->wrapper);

	size_t response_size = sizeof(struct netagent_message_header)
	    + sizeof(struct netagent)
	    + session->wrapper->netagent->netagent_data_size;
	response = (u_int8_t *)kalloc_data(response_size, Z_WAITOK);
	if (response == NULL) {
		NETAGENT_UNLOCK(session->wrapper);
		NETAGENT_SESSION_UNLOCK(session);
		goto fail;
	}

	cursor = response;
	cursor = netagent_buffer_write_message_header(cursor, NETAGENT_MESSAGE_TYPE_GET,
	    NETAGENT_MESSAGE_FLAGS_RESPONSE, message_id, 0,
	    response_size - sizeof(struct netagent_message_header));
	memcpy(cursor, session->wrapper->netagent, sizeof(struct netagent) +
	    session->wrapper->netagent->netagent_data_size);

	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	if (!netagent_send_ctl_data(session->control_unit, response, response_size)) {
		NETAGENTLOG0(LOG_ERR, "Failed to send response");
	}
	kfree_data(response, response_size);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_GET, message_id, response_error);
}

errno_t
netagent_assign_nexus(netagent_session_t _session, uuid_t necp_client_uuid,
    void *assign_message, size_t assigned_results_length)
{
	struct netagent_session *session = (struct netagent_session *)_session;
	uuid_t netagent_uuid;
	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot assign nexus from NULL session");
		return EINVAL;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent");
		return ENOENT;
	}
	NETAGENT_LOCK_SHARED(session->wrapper);
	uuid_copy(netagent_uuid, session->wrapper->netagent->netagent_uuid);
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	int error = necp_assign_client_result(netagent_uuid, necp_client_uuid, assign_message, assigned_results_length);
	if (error) {
		// necp_assign_client_result returns POSIX errors; don't error for ENOENT
		NETAGENTLOG((error == ENOENT ? LOG_DEBUG : LOG_ERR), "Client assignment failed: %d", error);
		return error;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned nexus properties to client");
	return 0;
}

errno_t
netagent_update_flow_protoctl_event(netagent_session_t _session,
    uuid_t client_id, uint32_t protoctl_event_code,
    uint32_t protoctl_event_val, uint32_t protoctl_event_tcp_seq_number)
{
	struct netagent_session *session = (struct netagent_session *)_session;
	uuid_t netagent_uuid;
	int error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Cannot assign nexus from NULL session");
		return EINVAL;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent");
		return ENOENT;
	}
	NETAGENT_LOCK_SHARED(session->wrapper);
	uuid_copy(netagent_uuid, session->wrapper->netagent->netagent_uuid);
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	error = necp_update_flow_protoctl_event(netagent_uuid,
	    client_id, protoctl_event_code, protoctl_event_val, protoctl_event_tcp_seq_number);

	return error;
}

static errno_t
netagent_handle_assign_nexus_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length)
{
	errno_t response_error = 0;
	struct netagent_assign_nexus_message *assign_nexus_netagent = (struct netagent_assign_nexus_message *)(void *)payload;
	uuid_t client_id;
	uuid_t netagent_uuid;
	u_int8_t *assigned_results = NULL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_SHARED(session->wrapper);
	uuid_copy(netagent_uuid, session->wrapper->netagent->netagent_uuid);
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG0(LOG_ERR, "Assign message is too short");
		response_error = EINVAL;
		goto done;
	}

	memcpy(client_id, assign_nexus_netagent->assign_client_id, sizeof(client_id));
	size_t assigned_results_length = (payload_length - sizeof(client_id));

	if (assigned_results_length > 0) {
		assigned_results = kalloc_data(assigned_results_length, Z_WAITOK);
		if (assigned_results == NULL) {
			NETAGENTLOG(LOG_ERR, "Failed to allocate assign message (%lu bytes)", assigned_results_length);
			response_error = ENOMEM;
			goto done;
		}
		memcpy(assigned_results, assign_nexus_netagent->assign_necp_results, assigned_results_length);
	}

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	response_error = necp_assign_client_result(netagent_uuid, client_id, assigned_results, assigned_results_length);
	if (response_error) {
		// necp_assign_client_result returns POSIX errors
		kfree_data(assigned_results, assigned_results_length);
		NETAGENTLOG(LOG_ERR, "Client assignment failed: %d", response_error);
		goto done;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned nexus properties to client");
done:
	return response_error;
}


static void
netagent_handle_assign_nexus_message(struct netagent_session *session, u_int32_t message_id,
    size_t payload_length, mbuf_t packet, size_t offset)
{
	int error = 0;
	u_int32_t response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
	uuid_t client_id;
	uuid_t netagent_uuid;
	u_int8_t *assigned_results = NULL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = NETAGENT_MESSAGE_ERROR_NOT_REGISTERED;
		goto fail;
	}
	NETAGENT_LOCK_SHARED(session->wrapper);
	uuid_copy(netagent_uuid, session->wrapper->netagent->netagent_uuid);
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG0(LOG_ERR, "Assign message is too short");
		response_error = NETAGENT_MESSAGE_ERROR_INVALID_DATA;
		goto fail;
	}

	error = mbuf_copydata(packet, offset, sizeof(client_id), &client_id);
	if (error) {
		NETAGENTLOG(LOG_ERR, "Failed to read uuid for assign message: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
		goto fail;
	}

	size_t assigned_results_length = (payload_length - sizeof(client_id));
	if (assigned_results_length > 0) {
		assigned_results = kalloc_data( assigned_results_length, Z_WAITOK);
		if (assigned_results == NULL) {
			NETAGENTLOG(LOG_ERR, "Failed to allocate assign message (%lu bytes)", assigned_results_length);
			response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
			goto fail;
		}

		error = mbuf_copydata(packet, offset + sizeof(client_id), assigned_results_length, assigned_results);
		if (error) {
			kfree_data(assigned_results, assigned_results_length);
			NETAGENTLOG(LOG_ERR, "Failed to read assign message: %d", error);
			response_error = NETAGENT_MESSAGE_ERROR_INTERNAL;
			goto fail;
		}
	}

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	error = necp_assign_client_result(netagent_uuid, client_id, assigned_results, assigned_results_length);
	if (error) {
		kfree_data(assigned_results, assigned_results_length);
		NETAGENTLOG(LOG_ERR, "Client assignment failed: %d", error);
		response_error = NETAGENT_MESSAGE_ERROR_CANNOT_ASSIGN;
		goto fail;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned nexus properties to client");
	netagent_send_success_response(session, NETAGENT_MESSAGE_TYPE_ASSIGN_NEXUS, message_id);
	return;
fail:
	netagent_send_error_response(session, NETAGENT_MESSAGE_TYPE_ASSIGN_NEXUS, message_id, response_error);
}

static errno_t
netagent_handle_assign_group_setopt(struct netagent_session *session, u_int8_t *payload,
    size_t payload_length)
{
	errno_t response_error = 0;
	struct netagent_assign_nexus_message *assign_message = (struct netagent_assign_nexus_message *)(void *)payload;
	uuid_t client_id;
	uuid_t netagent_uuid;
	u_int8_t *assigned_group_members = NULL;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent to get");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_SHARED(session->wrapper);
	uuid_copy(netagent_uuid, session->wrapper->netagent->netagent_uuid);
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	if (payload_length < sizeof(uuid_t)) {
		NETAGENTLOG0(LOG_ERR, "Group assign message is too short");
		response_error = EINVAL;
		goto done;
	}

	memcpy(client_id, assign_message->assign_client_id, sizeof(client_id));
	size_t assigned_group_members_length = (payload_length - sizeof(client_id));

	if (assigned_group_members_length > 0) {
		assigned_group_members = (u_int8_t *)kalloc_data(assigned_group_members_length, Z_WAITOK);
		if (assigned_group_members == NULL) {
			NETAGENTLOG(LOG_ERR, "Failed to allocate group assign message (%lu bytes)", assigned_group_members_length);
			response_error = ENOMEM;
			goto done;
		}
		memcpy(assigned_group_members, assign_message->assign_necp_results, assigned_group_members_length);
	}

	// Note that if the error is 0, NECP has taken over our malloc'ed buffer
	response_error = necp_assign_client_group_members(netagent_uuid, client_id, assigned_group_members, assigned_group_members_length);
	if (response_error != 0) {
		// necp_assign_client_group_members returns POSIX errors
		if (assigned_group_members != NULL) {
			kfree_data(assigned_group_members, assigned_group_members_length);
		}
		NETAGENTLOG(LOG_ERR, "Client group assignment failed: %d", response_error);
		goto done;
	}

	NETAGENTLOG0(LOG_DEBUG, "Agent assigned group members to client");
done:
	return response_error;
}


errno_t
netagent_handle_use_count_setopt(struct netagent_session *session, u_int8_t *payload, size_t payload_length)
{
	errno_t response_error = 0;
	uint64_t use_count = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (payload == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (payload_length != sizeof(use_count)) {
		NETAGENTLOG(LOG_ERR, "Payload length is invalid (%lu)", payload_length);
		response_error = EINVAL;
		goto done;
	}

	memcpy(&use_count, payload, sizeof(use_count));

	NETAGENT_SESSION_LOCK(session);

	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_EXCLUSIVE(session->wrapper);
	session->wrapper->use_count = use_count;
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

done:
	return response_error;
}

errno_t
netagent_handle_use_count_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length)
{
	errno_t response_error = 0;
	uint64_t use_count = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (buffer == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (*buffer_length != sizeof(use_count)) {
		NETAGENTLOG(LOG_ERR, "Buffer length is invalid (%lu)", *buffer_length);
		response_error = EINVAL;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);

	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_SHARED(session->wrapper);
	use_count = session->wrapper->use_count;
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	memcpy(buffer, &use_count, sizeof(use_count));
	*buffer_length = sizeof(use_count);

done:
	return response_error;
}

static errno_t
netagent_handle_add_token_setopt(struct netagent_session *session, u_int8_t *token, size_t token_length)
{
	errno_t response_error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (token == NULL) {
		NETAGENTLOG0(LOG_ERR, "No token received");
		response_error = EINVAL;
		goto done;
	}

	if (token_length > NETAGENT_MAX_DATA_SIZE) {
		NETAGENTLOG(LOG_ERR, "Token length is invalid (%lu)", token_length);
		response_error = EINVAL;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_EXCLUSIVE(session->wrapper);
	if (session->wrapper->token_count >= NETAGENT_MAX_TOKEN_COUNT) {
		NETAGENT_UNLOCK(session->wrapper);
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session cannot add more tokens");
		response_error = EINVAL;
		goto done;
	}

	struct netagent_token *token_struct = NULL;

	token_struct = kalloc_type(struct netagent_token, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	token_struct->token_bytes = kalloc_data(token_length, Z_WAITOK | Z_NOFAIL);
	token_struct->token_length = (u_int32_t)token_length;
	memcpy(token_struct->token_bytes, token, token_length);

	TAILQ_INSERT_TAIL(&session->wrapper->token_list, token_struct, token_chain);

	session->wrapper->token_count++;

	// Reset deadline time, now that there are more than 0 tokens
	session->wrapper->need_tokens_event_deadline = 0;

	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);
done:
	return response_error;
}

static errno_t
netagent_handle_flush_tokens_setopt(struct netagent_session *session, __unused u_int8_t *buffer, __unused size_t buffer_length)
{
	errno_t response_error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_EXCLUSIVE(session->wrapper);
	struct netagent_token *search_token = NULL;
	struct netagent_token *temp_token = NULL;
	TAILQ_FOREACH_SAFE(search_token, &session->wrapper->token_list, token_chain, temp_token) {
		TAILQ_REMOVE(&session->wrapper->token_list, search_token, token_chain);
		netagent_token_free(search_token);
	}
	session->wrapper->token_count = 0;
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);
done:
	return response_error;
}

static errno_t
netagent_handle_token_count_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length)
{
	errno_t response_error = 0;
	uint32_t token_count = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (buffer == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (*buffer_length != sizeof(token_count)) {
		NETAGENTLOG(LOG_ERR, "Buffer length is invalid (%lu)", *buffer_length);
		response_error = EINVAL;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_SHARED(session->wrapper);
	token_count = session->wrapper->token_count;
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	memcpy(buffer, &token_count, sizeof(token_count));
	*buffer_length = sizeof(token_count);

done:
	return response_error;
}

static errno_t
netagent_handle_token_low_water_setopt(struct netagent_session *session, u_int8_t *buffer, size_t buffer_length)
{
	errno_t response_error = 0;
	uint32_t token_low_water = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (buffer == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (buffer_length != sizeof(token_low_water)) {
		NETAGENTLOG(LOG_ERR, "Buffer length is invalid (%lu)", buffer_length);
		response_error = EINVAL;
		goto done;
	}

	memcpy(&token_low_water, buffer, sizeof(token_low_water));

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_EXCLUSIVE(session->wrapper);
	session->wrapper->token_low_water = token_low_water;
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

done:
	return response_error;
}

static errno_t
netagent_handle_token_low_water_getopt(struct netagent_session *session, u_int8_t *buffer, size_t *buffer_length)
{
	errno_t response_error = 0;
	uint32_t token_low_water = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	if (buffer == NULL) {
		NETAGENTLOG0(LOG_ERR, "No payload received");
		response_error = EINVAL;
		goto done;
	}

	if (*buffer_length != sizeof(token_low_water)) {
		NETAGENTLOG(LOG_ERR, "Buffer length is invalid (%lu)", *buffer_length);
		response_error = EINVAL;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_SHARED(session->wrapper);
	token_low_water = session->wrapper->token_low_water;
	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);

	memcpy(buffer, &token_low_water, sizeof(token_low_water));
	*buffer_length = sizeof(token_low_water);

done:
	return response_error;
}

static errno_t
netagent_handle_reset_client_error_setopt(struct netagent_session *session, __unused u_int8_t *payload, __unused size_t payload_length)
{
	errno_t response_error = 0;

	if (session == NULL) {
		NETAGENTLOG0(LOG_ERR, "Failed to find session");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_SESSION_LOCK(session);
	if (session->wrapper == NULL) {
		NETAGENT_SESSION_UNLOCK(session);
		NETAGENTLOG0(LOG_ERR, "Session has no agent registered");
		response_error = ENOENT;
		goto done;
	}

	NETAGENT_LOCK_EXCLUSIVE(session->wrapper);
	struct netagent_token *search_token = NULL;
	struct netagent_token *temp_token = NULL;
	TAILQ_FOREACH_SAFE(search_token, &session->wrapper->token_list, token_chain, temp_token) {
		TAILQ_REMOVE(&session->wrapper->token_list, search_token, token_chain);
		netagent_token_free(search_token);
	}
	session->wrapper->last_client_error = 0;
	session->wrapper->client_error_count = 0;

	NETAGENT_UNLOCK(session->wrapper);
	NETAGENT_SESSION_UNLOCK(session);
done:
	return response_error;
}

static struct netagent_wrapper *
netagent_find_agent_with_uuid_and_lock(uuid_t uuid, bool exclusively, bool ignore_lock)
{
	NETAGENT_LIST_ASSERT_LOCKED();

	struct netagent_wrapper *search_netagent = NULL;

	LIST_FOREACH(search_netagent, &shared_netagent_list, list_chain) {
		if (uuid_compare(search_netagent->netagent->netagent_uuid, uuid) == 0) {
			if (!ignore_lock) {
				if (exclusively) {
					NETAGENT_LOCK_EXCLUSIVE(search_netagent);
				} else {
					NETAGENT_LOCK_SHARED(search_netagent);
				}
			}
			return search_netagent;
		}
	}

	return NULL;
}

void
netagent_post_updated_interfaces(uuid_t uuid)
{
	if (!uuid_is_null(uuid)) {
		netagent_post_event(uuid, KEV_NETAGENT_UPDATED_INTERFACES, true, false);
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Interface event with no associated agent");
	}
}

static u_int32_t
netagent_dump_get_data_size_locked()
{
	NETAGENT_LIST_ASSERT_LOCKED();

	struct netagent_wrapper *search_netagent = NULL;
	u_int32_t total_netagent_data_size = 0;
	// Traverse the shared list to know how much data the client needs to allocate to get the list of agent UUIDs
	LIST_FOREACH(search_netagent, &shared_netagent_list, list_chain) {
		total_netagent_data_size += sizeof(search_netagent->netagent->netagent_uuid);
	}
	return total_netagent_data_size;
}

static void
netagent_dump_copy_data_locked(u_int8_t *buffer, u_int32_t buffer_length)
{
	NETAGENT_LIST_ASSERT_LOCKED();

	size_t response_size = 0;
	u_int8_t *cursor = NULL;
	struct netagent_wrapper *search_netagent = NULL;

	response_size = buffer_length; // We already know that buffer_length is the same as total_netagent_data_size.
	cursor = buffer;
	LIST_FOREACH(search_netagent, &shared_netagent_list, list_chain) {
		memcpy(cursor, search_netagent->netagent->netagent_uuid, sizeof(search_netagent->netagent->netagent_uuid));
		cursor += sizeof(search_netagent->netagent->netagent_uuid);
	}
}

int
netagent_ioctl(u_long cmd, caddr_t data)
{
	int error = 0;

	switch (cmd) {
	case SIOCGIFAGENTLIST32:
	case SIOCGIFAGENTLIST64: {
		/* Check entitlement if the client requests agent dump */
		errno_t cred_result = priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NECP_POLICIES, 0);
		if (cred_result != 0) {
			NETAGENTLOG0(LOG_ERR, "Client does not hold the necessary entitlement to get netagent information");
			return EINVAL;
		}
		break;
	}
	default:
		break;
	}

	NETAGENT_LIST_LOCK_SHARED();
	switch (cmd) {
	case SIOCGIFAGENTDATA32: {
		struct netagent_req32 *ifsir32 = (struct netagent_req32 *)(void *)data;
		struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(ifsir32->netagent_uuid, false, false);
		if (wrapper == NULL) {
			error = ENOENT;
			break;
		}
		uuid_copy(ifsir32->netagent_uuid, wrapper->netagent->netagent_uuid);
		memcpy(ifsir32->netagent_domain, wrapper->netagent->netagent_domain, sizeof(ifsir32->netagent_domain));
		memcpy(ifsir32->netagent_type, wrapper->netagent->netagent_type, sizeof(ifsir32->netagent_type));
		memcpy(ifsir32->netagent_desc, wrapper->netagent->netagent_desc, sizeof(ifsir32->netagent_desc));
		ifsir32->netagent_flags = wrapper->netagent->netagent_flags;
		if (ifsir32->netagent_data_size == 0) {
			// First pass, client wants data size
			ifsir32->netagent_data_size = wrapper->netagent->netagent_data_size;
		} else if (ifsir32->netagent_data != USER_ADDR_NULL &&
		    ifsir32->netagent_data_size == wrapper->netagent->netagent_data_size) {
			// Second pass, client wants data buffer filled out
			error = copyout(wrapper->netagent->netagent_data, ifsir32->netagent_data, wrapper->netagent->netagent_data_size);
		} else {
			error = EINVAL;
		}
		NETAGENT_UNLOCK(wrapper);
		break;
	}
	case SIOCGIFAGENTDATA64: {
		struct netagent_req64 *ifsir64 = (struct netagent_req64 *)(void *)data;
		struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(ifsir64->netagent_uuid, false, false);
		if (wrapper == NULL) {
			error = ENOENT;
			break;
		}
		uuid_copy(ifsir64->netagent_uuid, wrapper->netagent->netagent_uuid);
		memcpy(ifsir64->netagent_domain, wrapper->netagent->netagent_domain, sizeof(ifsir64->netagent_domain));
		memcpy(ifsir64->netagent_type, wrapper->netagent->netagent_type, sizeof(ifsir64->netagent_type));
		memcpy(ifsir64->netagent_desc, wrapper->netagent->netagent_desc, sizeof(ifsir64->netagent_desc));
		ifsir64->netagent_flags = wrapper->netagent->netagent_flags;
		if (ifsir64->netagent_data_size == 0) {
			// First pass, client wants data size
			ifsir64->netagent_data_size = wrapper->netagent->netagent_data_size;
		} else if (ifsir64->netagent_data != USER_ADDR_NULL &&
		    ifsir64->netagent_data_size == wrapper->netagent->netagent_data_size) {
			// Second pass, client wants data buffer filled out
			error = copyout(wrapper->netagent->netagent_data, ifsir64->netagent_data, wrapper->netagent->netagent_data_size);
		} else {
			error = EINVAL;
		}
		NETAGENT_UNLOCK(wrapper);
		break;
	}
	case SIOCGIFAGENTLIST32: {
		struct netagentlist_req32 *ifsir32 = (struct netagentlist_req32 *)(void *)data;
		if (ifsir32->data_size == 0) {
			// First pass, client wants data size
			ifsir32->data_size = netagent_dump_get_data_size_locked();
		} else if (ifsir32->data != USER_ADDR_NULL &&
		    ifsir32->data_size > 0 &&
		    ifsir32->data_size == netagent_dump_get_data_size_locked()) {
			// Second pass, client wants data buffer filled out
			u_int8_t *response = NULL;
			response = (u_int8_t *)kalloc_data(ifsir32->data_size, Z_NOWAIT | Z_ZERO);
			if (response == NULL) {
				error = ENOMEM;
				break;
			}

			netagent_dump_copy_data_locked(response, ifsir32->data_size);
			error = copyout(response, ifsir32->data, ifsir32->data_size);
			kfree_data(response, ifsir32->data_size);
		} else {
			error = EINVAL;
		}
		break;
	}
	case SIOCGIFAGENTLIST64: {
		struct netagentlist_req64 *ifsir64 = (struct netagentlist_req64 *)(void *)data;
		if (ifsir64->data_size == 0) {
			// First pass, client wants data size
			ifsir64->data_size = netagent_dump_get_data_size_locked();
		} else if (ifsir64->data != USER_ADDR_NULL &&
		    ifsir64->data_size > 0 &&
		    ifsir64->data_size == netagent_dump_get_data_size_locked()) {
			// Second pass, client wants data buffer filled out
			u_int8_t *response = NULL;
			response = (u_int8_t *)kalloc_data(ifsir64->data_size, Z_NOWAIT | Z_ZERO);
			if (response == NULL) {
				error = ENOMEM;
				break;
			}

			netagent_dump_copy_data_locked(response, ifsir64->data_size);
			error = copyout(response, ifsir64->data, ifsir64->data_size);
			kfree_data(response, ifsir64->data_size);
		} else {
			error = EINVAL;
		}
		break;
	}
	default: {
		error = EINVAL;
		break;
	}
	}
	NETAGENT_LIST_UNLOCK();
	return error;
}

u_int32_t
netagent_get_flags(uuid_t uuid)
{
	u_int32_t flags = 0;
	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(uuid, false, false);
	if (wrapper != NULL) {
		flags = wrapper->netagent->netagent_flags;
		NETAGENT_UNLOCK(wrapper);
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Flags requested for invalid netagent");
	}
	NETAGENT_LIST_UNLOCK();

	return flags;
}

errno_t
netagent_set_flags(uuid_t uuid, u_int32_t flags)
{
	errno_t error = 0;
	bool updated = false;

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(uuid, true, false);
	if (wrapper != NULL) {
		// Don't allow the clients to clear
		// NETAGENT_FLAG_REGISTERED.
		uint32_t registered =
		    wrapper->netagent->netagent_flags & NETAGENT_FLAG_REGISTERED;
		flags |= registered;
		if (wrapper->netagent->netagent_flags != flags) {
			wrapper->netagent->netagent_flags = flags;
			wrapper->generation = g_next_generation++;
			updated = true;
		}
		NETAGENT_UNLOCK(wrapper);
	} else {
		NETAGENTLOG0(LOG_DEBUG,
		    "Attempt to set flags for invalid netagent");
		error = ENOENT;
	}
	NETAGENT_LIST_UNLOCK();
	if (updated) {
		netagent_post_event(uuid, KEV_NETAGENT_UPDATED, true, false);
	}

	return error;
}

u_int32_t
netagent_get_generation(uuid_t uuid)
{
	u_int32_t generation = 0;
	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(uuid, false, false);
	if (wrapper != NULL) {
		generation = wrapper->generation;
		NETAGENT_UNLOCK(wrapper);
	} else {
		NETAGENTLOG0(LOG_DEBUG, "Generation requested for invalid netagent");
	}
	NETAGENT_LIST_UNLOCK();

	return generation;
}

bool
netagent_get_agent_domain_and_type(uuid_t uuid, char *domain, char *type)
{
	bool found = FALSE;
	if (domain == NULL || type == NULL) {
		NETAGENTLOG(LOG_ERR, "Invalid arguments for netagent_get_agent_domain_and_type %p %p", domain, type);
		return FALSE;
	}

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(uuid, false, false);
	if (wrapper != NULL) {
		found = TRUE;
		memcpy(domain, wrapper->netagent->netagent_domain, NETAGENT_DOMAINSIZE);
		memcpy(type, wrapper->netagent->netagent_type, NETAGENT_TYPESIZE);
		NETAGENT_UNLOCK(wrapper);
	} else {
		NETAGENTLOG0(LOG_ERR, "Type requested for invalid netagent");
	}
	NETAGENT_LIST_UNLOCK();

	return found;
}

int
netagent_kernel_trigger(uuid_t uuid)
{
	int error = 0;

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(uuid, false, false);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent for kernel trigger could not be found");
		error = ENOENT;
		goto done;
	}

	if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_KERNEL_ACTIVATED) == 0) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent for kernel trigger is not kernel activated");
		// Agent does not accept kernel triggers
		error = EINVAL;
		goto done;
	}

	if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		// Agent already active
		NETAGENTLOG0(LOG_INFO, "Requested netagent for kernel trigger is already active");
		error = 0;
		goto done;
	}

	error = netagent_send_trigger(wrapper, current_proc(), NETAGENT_TRIGGER_FLAG_KERNEL, NETAGENT_MESSAGE_TYPE_TRIGGER);
	NETAGENTLOG((error ? LOG_ERR : LOG_INFO), "Triggered netagent from kernel (error %d)", error);
done:
	if (wrapper != NULL) {
		NETAGENT_UNLOCK(wrapper);
	}
	NETAGENT_LIST_UNLOCK();
	return error;
}

int
netagent_client_message_with_params(uuid_t agent_uuid,
    uuid_t necp_client_uuid,
    pid_t pid,
    void *handle,
    u_int8_t message_type,
    struct necp_client_agent_parameters *parameters,
    void **assigned_results,
    size_t *assigned_results_length)
{
	int error = 0;

	if (message_type != NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER &&
	    message_type != NETAGENT_MESSAGE_TYPE_CLIENT_ASSERT &&
	    message_type != NETAGENT_MESSAGE_TYPE_CLIENT_UNASSERT &&
	    message_type != NETAGENT_MESSAGE_TYPE_CLIENT_ERROR &&
	    message_type != NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS &&
	    message_type != NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS &&
	    message_type != NETAGENT_MESSAGE_TYPE_ABORT_NEXUS &&
	    message_type != NETAGENT_MESSAGE_TYPE_ADD_GROUP_MEMBERS &&
	    message_type != NETAGENT_MESSAGE_TYPE_REMOVE_GROUP_MEMBERS) {
		NETAGENTLOG(LOG_ERR, "Client netagent message type (%d) is invalid", message_type);
		return EINVAL;
	}

	NETAGENT_LIST_LOCK_SHARED();
	bool should_unlock_list = true;
	bool should_unlock_wrapper = true;
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(agent_uuid, false, false);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_DEBUG, "Requested netagent for nexus instance could not be found");
		error = ENOENT;
		goto done;
	}

	if (message_type == NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER) {
		if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_USER_ACTIVATED) == 0) {
			// Agent does not accept user triggers
			// Don't log, since this is a common case used to trigger events that cellular data is blocked, etc.
			error = ENOTSUP;


			pid_t report_pid = 0;
			uuid_t report_proc_uuid = {};
			if (parameters != NULL) {
				report_pid = parameters->u.nexus_request.epid;
				uuid_copy(report_proc_uuid, parameters->u.nexus_request.euuid);
			} else {
				struct proc *p = current_proc();
				if (p != NULL) {
					report_pid = proc_pid(p);
					proc_getexecutableuuid(p, report_proc_uuid, sizeof(report_proc_uuid));
				}
			}
			netagent_send_cellular_failed_event(wrapper, report_pid, report_proc_uuid);
			goto done;
		}
	} else if (message_type == NETAGENT_MESSAGE_TYPE_REQUEST_NEXUS ||
	    message_type == NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS ||
	    message_type == NETAGENT_MESSAGE_TYPE_ABORT_NEXUS) {
		bool is_nexus_agent = ((wrapper->netagent->netagent_flags &
		    (NETAGENT_FLAG_NEXUS_PROVIDER |
		    NETAGENT_FLAG_NEXUS_LISTENER |
		    NETAGENT_FLAG_CUSTOM_IP_NEXUS |
		    NETAGENT_FLAG_CUSTOM_ETHER_NEXUS |
		    NETAGENT_FLAG_INTERPOSE_NEXUS)) != 0);
		if (!is_nexus_agent) {
			NETAGENTLOG0(LOG_ERR, "Requested netagent for nexus instance is not a nexus provider");
			// Agent is not a nexus provider
			error = EINVAL;
			goto done;
		}

		if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) == 0) {
			// Agent not active
			NETAGENTLOG0(LOG_INFO, "Requested netagent for nexus instance is not active");
			error = EINVAL;
			goto done;
		}
	} else if (message_type == NETAGENT_MESSAGE_TYPE_ADD_GROUP_MEMBERS ||
	    message_type == NETAGENT_MESSAGE_TYPE_REMOVE_GROUP_MEMBERS) {
		bool is_group_agent = ((wrapper->netagent->netagent_flags & (NETAGENT_FLAG_SUPPORTS_GROUPS)) != 0);
		if (!is_group_agent) {
			NETAGENTLOG0(LOG_ERR, "Requested netagent for group operation is not a group provider");
			error = EINVAL;
			goto done;
		}

		if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE) == 0) {
			// Agent not active
			NETAGENTLOG0(LOG_INFO, "Requested netagent for group operation is not active");
			error = EINVAL;
			goto done;
		}
	}

	if (wrapper->control_unit == 0) {
		if (wrapper->event_handler == NULL) {
			// No event handler registered for kernel agent
			error = EINVAL;
		} else {
			// We hold the wrapper lock during the event handler callout, so it is expected
			// that the event handler will not lead to any registrations or unregistrations
			// of network agents.
			// We release the list lock before calling the event handler to allow other threads
			// to access the list while the event is processing.
			NETAGENT_LIST_UNLOCK();
			should_unlock_list = false;
			error = wrapper->event_handler(message_type, necp_client_uuid, pid, handle,
			    wrapper->event_context, parameters,
			    assigned_results, assigned_results_length);
			if (error != 0) {
				VERIFY(assigned_results == NULL || *assigned_results == NULL);
				VERIFY(assigned_results_length == NULL || *assigned_results_length == 0);
			}
		}
	} else {
		// ABORT_NEXUS is kernel-private, so translate it for userspace nexus
		if (message_type == NETAGENT_MESSAGE_TYPE_ABORT_NEXUS) {
			message_type = NETAGENT_MESSAGE_TYPE_CLOSE_NEXUS;
		}

		if (message_type == NETAGENT_MESSAGE_TYPE_CLIENT_ERROR) {
			const int32_t client_error = parameters->u.error;
			if (wrapper->last_client_error != client_error || // Always notify for an error change
			    (client_error == 0 && wrapper->client_error_count == 0) || // Only notify once for no-error
			    (client_error != 0 && wrapper->client_error_count < NETAGENT_MAX_CLIENT_ERROR_COUNT)) {
				if (NETAGENT_LOCK_SHARED_TO_EXCLUSIVE(wrapper)) {
					if (wrapper->last_client_error != client_error) {
						wrapper->last_client_error = client_error;
						wrapper->client_error_count = 1;
					} else {
						wrapper->client_error_count++;
					}
					error = netagent_send_error_message(wrapper, necp_client_uuid, message_type, client_error);
				} else {
					// If NETAGENT_LOCK_SHARED_TO_EXCLUSIVE fails, it unlocks automatically
					should_unlock_wrapper = false;
				}
			}
		} else if (message_type == NETAGENT_MESSAGE_TYPE_ADD_GROUP_MEMBERS ||
		    message_type == NETAGENT_MESSAGE_TYPE_REMOVE_GROUP_MEMBERS) {
			error = netagent_send_group_message(wrapper, necp_client_uuid, message_type, &parameters->u.group_members);
		} else {
			error = netagent_send_client_message(wrapper, necp_client_uuid, message_type);
		}
		if (error == 0 && message_type == NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER) {
			if (NETAGENT_LOCK_SHARED_TO_EXCLUSIVE(wrapper)) {
				// Grab the lock exclusively to add a pending client to the list
				struct netagent_client *new_pending_client = NULL;
				new_pending_client = kalloc_type(struct netagent_client, Z_WAITOK);
				if (new_pending_client == NULL) {
					NETAGENTLOG0(LOG_ERR, "Failed to allocate client for trigger");
				} else {
					uuid_copy(new_pending_client->client_id, necp_client_uuid);
					if (parameters != NULL) {
						new_pending_client->client_pid = parameters->u.nexus_request.epid;
						uuid_copy(new_pending_client->client_proc_uuid, parameters->u.nexus_request.euuid);
					} else {
						struct proc *p = current_proc();
						if (p != NULL) {
							new_pending_client->client_pid = proc_pid(p);
							proc_getexecutableuuid(p, new_pending_client->client_proc_uuid, sizeof(new_pending_client->client_proc_uuid));
						}
					}
					LIST_INSERT_HEAD(&wrapper->pending_triggers_list, new_pending_client, client_chain);
				}
			} else {
				// If NETAGENT_LOCK_SHARED_TO_EXCLUSIVE fails, it unlocks automatically
				should_unlock_wrapper = false;
			}
		}
	}
	NETAGENTLOG(((error && error != ENOENT) ? LOG_ERR : LOG_INFO), "Send message %d for client (error %d)", message_type, error);
	if (message_type == NETAGENT_MESSAGE_TYPE_CLIENT_TRIGGER) {
		uuid_string_t uuid_str;
		uuid_unparse(agent_uuid, uuid_str);
		NETAGENTLOG(LOG_NOTICE, "Triggered network agent %s, error = %d", uuid_str, error);
	}
done:
	if (should_unlock_wrapper && wrapper != NULL) {
		NETAGENT_UNLOCK(wrapper);
	}
	if (should_unlock_list) {
		NETAGENT_LIST_UNLOCK();
	}
	return error;
}

int
netagent_client_message(uuid_t agent_uuid, uuid_t necp_client_uuid, pid_t pid, void *handle, u_int8_t message_type)
{
	return netagent_client_message_with_params(agent_uuid, necp_client_uuid, pid, handle, message_type, NULL, NULL, NULL);
}

int
netagent_use(uuid_t agent_uuid, uint64_t *out_use_count)
{
	int error = 0;

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(agent_uuid, true, false);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "netagent_assert: Requested netagent UUID is not registered");
		error = ENOENT;
		goto done;
	}

	uint64_t current_count = wrapper->use_count;
	wrapper->use_count++;

	if (out_use_count != NULL) {
		*out_use_count = current_count;
	}

done:
	if (wrapper != NULL) {
		NETAGENT_UNLOCK(wrapper);
	}
	NETAGENT_LIST_UNLOCK();
	return error;
}

int
netagent_copyout(uuid_t agent_uuid, user_addr_t user_addr, u_int32_t user_size)
{
	int error = 0;

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(agent_uuid, false, false);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_DEBUG, "Requested netagent for nexus instance could not be found");
		error = ENOENT;
		goto done;
	}

	u_int32_t total_size = (sizeof(struct netagent) + wrapper->netagent->netagent_data_size);
	if (user_size < total_size) {
		NETAGENTLOG(LOG_ERR, "Provided user buffer is too small (%u < %u)", user_size, total_size);
		error = EINVAL;
		goto done;
	}

	error = copyout(wrapper->netagent, user_addr, total_size);

	NETAGENTLOG((error ? LOG_ERR : LOG_DEBUG), "Copied agent content (error %d)", error);
done:
	if (wrapper != NULL) {
		NETAGENT_UNLOCK(wrapper);
	}
	NETAGENT_LIST_UNLOCK();
	return error;
}

#define NETAGENT_TOKEN_EVENT_INTERVAL_NSEC (NSEC_PER_SEC * 10) // Only fire repeated events up to once every 10 seconds

int
netagent_acquire_token(uuid_t agent_uuid, user_addr_t user_addr, u_int32_t user_size, int *retval)
{
	int error = 0;

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(agent_uuid, true, false);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_DEBUG, "Network agent for request UUID could not be found");
		error = ENOENT;
		goto done;
	}

	struct netagent_token *token = TAILQ_FIRST(&wrapper->token_list);
	if (token == NULL) {
		NETAGENTLOG0(LOG_DEBUG, "Network agent does not have any tokens");
		if (wrapper->token_low_water != 0) {
			// Only fire an event if one hasn't occurred in the last 10 seconds
			if (mach_absolute_time() >= wrapper->need_tokens_event_deadline) {
				int event_error = netagent_send_tokens_needed(wrapper);
				if (event_error == 0) {
					// Reset the deadline
					uint64_t deadline = 0;
					nanoseconds_to_absolutetime(NETAGENT_TOKEN_EVENT_INTERVAL_NSEC, &deadline);
					clock_absolutetime_interval_to_deadline(deadline, &deadline);
					wrapper->need_tokens_event_deadline = deadline;
				}
			}
		}
		error = ENODATA;
		goto done;
	}

	if (user_size < token->token_length) {
		NETAGENTLOG(LOG_ERR, "Provided user buffer is too small (%u < %u)", user_size, token->token_length);
		error = EMSGSIZE;
		goto done;
	}

	error = copyout(token->token_bytes, user_addr, token->token_length);
	if (error == 0) {
		*retval = (int)token->token_length;
	}

	NETAGENTLOG((error ? LOG_ERR : LOG_DEBUG), "Copied token content (error %d)", error);

	TAILQ_REMOVE(&wrapper->token_list, token, token_chain);
	netagent_token_free(token);
	if (wrapper->token_count > 0) {
		wrapper->token_count--;
	}
	if (wrapper->token_count < wrapper->token_low_water) {
		(void)netagent_send_tokens_needed(wrapper);
	}
done:
	if (wrapper != NULL) {
		NETAGENT_UNLOCK(wrapper);
	}
	NETAGENT_LIST_UNLOCK();
	return error;
}

int
netagent_trigger(struct proc *p, struct netagent_trigger_args *uap, int32_t *retval)
{
#pragma unused(p, retval)
	uuid_t agent_uuid = {};
	int error = 0;

	if (uap == NULL) {
		NETAGENTLOG0(LOG_ERR, "uap == NULL");
		return EINVAL;
	}

	if (uap->agent_uuid) {
		if (uap->agent_uuidlen != sizeof(uuid_t)) {
			NETAGENTLOG(LOG_ERR, "Incorrect length (got %zu, expected %lu)",
			    (size_t)uap->agent_uuidlen, sizeof(uuid_t));
			return ERANGE;
		}

		error = copyin(uap->agent_uuid, agent_uuid, sizeof(uuid_t));
		if (error) {
			NETAGENTLOG(LOG_ERR, "copyin error (%d)", error);
			return error;
		}
	}

	if (uuid_is_null(agent_uuid)) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent UUID is empty");
		return EINVAL;
	}

	NETAGENT_LIST_LOCK_SHARED();
	struct netagent_wrapper *wrapper = netagent_find_agent_with_uuid_and_lock(agent_uuid, false, false);
	if (wrapper == NULL) {
		NETAGENTLOG0(LOG_ERR, "Requested netagent UUID is not registered");
		error = ENOENT;
		goto done;
	}

	if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_USER_ACTIVATED) == 0) {
		// Agent does not accept triggers
		NETAGENTLOG0(LOG_ERR, "Requested netagent UUID is not eligible for triggering");
		error = ENOTSUP;
		goto done;
	}

	if ((wrapper->netagent->netagent_flags & NETAGENT_FLAG_ACTIVE)) {
		// Agent already active
		NETAGENTLOG0(LOG_INFO, "Requested netagent UUID is already active");
		error = 0;
		goto done;
	}

	error = netagent_send_trigger(wrapper, p, NETAGENT_TRIGGER_FLAG_USER, NETAGENT_MESSAGE_TYPE_TRIGGER);
	NETAGENTLOG((error ? LOG_ERR : LOG_INFO), "Triggered netagent (error %d)", error);
done:
	if (wrapper != NULL) {
		NETAGENT_UNLOCK(wrapper);
	}
	NETAGENT_LIST_UNLOCK();
	return error;
}
