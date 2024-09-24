/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
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

#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/port.h>

#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/ipc_kobject.h>
#include <kern/mach_filter.h>
#include <kern/task.h>

#include <vm/vm_map_xnu.h> /* current_map() */
#include <vm/vm_protos.h> /* current_proc() */

#include <ipc/ipc_policy.h>
#include <ipc/ipc_service_port.h>
#include <ipc/port.h>

#if CONFIG_CSR
#include <sys/csr.h>
#endif
#include <sys/codesign.h>
#include <sys/proc_ro.h>

#include <libkern/coreanalytics/coreanalytics.h>

extern int  proc_isinitproc(struct proc *p);
extern bool proc_is_simulated(struct proc *);
extern char *proc_name_address(struct proc *p);


#pragma mark policy tunables

extern const vm_size_t  ipc_kmsg_max_vm_space;

#if IPC_HAS_LEGACY_MACH_MSG_TRAP
#if DEVELOPMENT || DEBUG
static TUNABLE(bool, allow_legacy_mach_msg, "allow_legacy_mach_msg", false);
#endif /* DEVELOPMENT || DEBUG */
#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */


#pragma mark policy utils

__abortlike void
__ipc_unreachable(
	const char *reason,
	const char *file,
	int         line)
{
	(panic)("%s @%s:%d", reason, file, line);
}


#pragma mark policy options

mach_msg_option64_t
ipc_current_user_policy(
	task_t                  task,
	mach_msg_option64_t     opts)
{
	uint32_t ro_flags = task_ro_flags_get(task);

	/*
	 * Step 1: convert to kernel flags
	 * - clear any kernel only flags
	 * - convert MACH_SEND_FILTER_NONFATAL which is aliased to the
	 *   MACH_SEND_ALWAYS kernel flag into MACH64_POLICY_FILTER_NON_FATAL.
	 */
	opts &= MACH64_MSG_OPTION_USER;

	if (opts & MACH64_SEND_FILTER_NONFATAL) {
		/*
		 */
		opts &= ~MACH64_SEND_FILTER_NONFATAL;
		opts |= MACH64_POLICY_FILTER_NON_FATAL;
	}
	if (ro_flags & TFRO_FILTER_MSG) {
		opts |= MACH64_POLICY_FILTER_MSG;
	}

	/*
	 * Step 2: derive policy flags from the current context
	 */
	if (ro_flags & TFRO_PLATFORM) {
		opts |= MACH64_POLICY_PLATFORM;
		opts |= MACH64_POLICY_RIGID;
		opts |= MACH64_POLICY_HARDENED;
	}
	if (ro_flags & TFRO_HARDENED) {
		opts |= MACH64_POLICY_RIGID;
		opts |= MACH64_POLICY_HARDENED;
	}
#if CONFIG_ROSETTA
	if (task_is_translated(task)) {
		opts |= MACH64_POLICY_TRANSLATED;
	}
#endif
#if XNU_TARGET_OS_OSX
	struct proc *proc = get_bsdtask_info(task);
	if (proc_is_simulated(proc)) {
		opts |= MACH64_POLICY_SIMULATED;
	}
	if (csproc_hardened_runtime(proc)) {
		opts |= MACH64_POLICY_HARDENED;
	}
#endif
	if (!(opts & MACH64_POLICY_NEEDED_MASK)) {
		/* helps assert that a policy has been set */
		opts |= MACH64_POLICY_DEFAULT;
	}

	return opts;
}

mach_msg_return_t
ipc_preflight_msg_option64(mach_msg_option64_t opts)
{
	bool success = true;

	if ((opts & MACH64_SEND_MSG) && (opts & MACH64_MACH_MSG2)) {
		mach_msg_option64_t cfi = opts & MACH64_MSG_OPTION_CFI_MASK;

#if !XNU_TARGET_OS_OSX
		cfi &= ~MACH64_SEND_ANY;
#endif
		/* mach_msg2() calls must have exactly _one_ of these set */
		if (cfi == 0 || (cfi & (cfi - 1)) != 0) {
			success = false;
		}

		/* vector calls are only supported for message queues */
		if ((opts & (MACH64_SEND_MQ_CALL | MACH64_SEND_ANY)) == 0 &&
		    (opts & MACH64_MSG_VECTOR)) {
			success = false;
		}
	}

	if (success) {
		return MACH_MSG_SUCCESS;
	}

	mach_port_guard_exception(0, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
	if (opts & MACH64_MACH_MSG2) {
		return MACH_SEND_INVALID_OPTIONS;
	}
	return KERN_NOT_SUPPORTED;
}


#pragma mark legacy trap policies
#if IPC_HAS_LEGACY_MACH_MSG_TRAP

CA_EVENT(mach_msg_trap_event,
    CA_INT, msgh_id,
    CA_INT, sw_platform,
    CA_INT, sdk,
    CA_STATIC_STRING(CA_TEAMID_MAX_LEN), team_id,
    CA_STATIC_STRING(CA_SIGNINGID_MAX_LEN), signing_id,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name);

static void
mach_msg_legacy_send_analytics(
	mach_msg_id_t           msgh_id,
	uint32_t                platform,
	uint32_t                sdk)
{
	char *proc_name = proc_name_address(current_proc());
	const char *team_id = csproc_get_teamid(current_proc());
	const char *signing_id = csproc_get_identity(current_proc());

	ca_event_t ca_event = CA_EVENT_ALLOCATE(mach_msg_trap_event);
	CA_EVENT_TYPE(mach_msg_trap_event) * msg_event = ca_event->data;

	msg_event->msgh_id = msgh_id;
	msg_event->sw_platform = platform;
	msg_event->sdk = sdk;

	if (proc_name) {
		strlcpy(msg_event->proc_name, proc_name, CA_PROCNAME_LEN);
	}

	if (team_id) {
		strlcpy(msg_event->team_id, team_id, CA_TEAMID_MAX_LEN);
	}

	if (signing_id) {
		strlcpy(msg_event->signing_id, signing_id, CA_SIGNINGID_MAX_LEN);
	}

	CA_EVENT_SEND(ca_event);
}

static bool
ipc_policy_allow_legacy_mach_msg_trap_for_platform(
	mach_msg_id_t           msgid)
{
	struct proc_ro *pro = current_thread_ro()->tro_proc_ro;
	uint32_t platform = pro->p_platform_data.p_platform;
	uint32_t sdk = pro->p_platform_data.p_sdk;
	uint32_t sdk_major = sdk >> 16;

	/*
	 * Special rules, due to unfortunate bincompat reasons,
	 * allow for a hardcoded list of MIG calls to XNU to go through:
	 * - for iOS, Catalyst and iOS Simulator apps linked against
	 *   an SDK older than 15.x,
	 * - for macOS apps linked against an SDK older than 12.x.
	 */
	switch (platform) {
	case PLATFORM_IOS:
	case PLATFORM_IOSSIMULATOR:
	case PLATFORM_MACCATALYST:
		if (sdk == 0 || sdk_major > 15) {
			return false;
		}
		break;
	case PLATFORM_MACOS:
		if (sdk == 0 || sdk_major > 12) {
			return false;
		}
		break;
	default:
		return false;
	}

	switch (msgid) {
	case 0xd4a: /* task_threads */
	case 0xd4d: /* task_info */
	case 0xe13: /* thread_get_state */
	case 0x12c4: /* mach_vm_read */
	case 0x12c8: /* mach_vm_read_overwrite */
		mach_msg_legacy_send_analytics(msgid, platform, sdk);
		return true;
	default:
		return false;
	}
}


mach_msg_return_t
ipc_policy_allow_legacy_send_trap(
	mach_msg_id_t           msgid,
	mach_msg_option64_t     opts)
{
	if ((opts & MACH64_POLICY_HARDENED) == 0) {
#if __x86_64__
		if (current_map()->max_offset <= VM_MAX_ADDRESS) {
			/*
			 * Legacy mach_msg_trap() is the only
			 * available thing for 32-bit tasks
			 */
			return MACH_MSG_SUCCESS;
		}
#endif /* __x86_64__ */
#if CONFIG_ROSETTA
		if (opts & MACH64_POLICY_TRANSLATED) {
			/*
			 * Similarly, on Rosetta, allow mach_msg_trap()
			 * as those apps likely can't be fixed anymore
			 */
			return MACH_MSG_SUCCESS;
		}
#endif
#if DEVELOPMENT || DEBUG
		if (allow_legacy_mach_msg) {
			/* Honor boot-arg */
			return MACH_MSG_SUCCESS;
		}
#endif /* DEVELOPMENT || DEBUG */
		if (ipc_policy_allow_legacy_mach_msg_trap_for_platform(msgid)) {
			return MACH_MSG_SUCCESS;
		}
	}

	mach_port_guard_exception(msgid, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
	/*
	 * this should be MACH_SEND_INVALID_OPTIONS,
	 * but this is a new mach_msg2 error only.
	 */
	return KERN_NOT_SUPPORTED;
}


#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */
#pragma mark reply port semantics telemetry

/*
 * As CA framework replies on successfully allocating zalloc memory,
 * we maintain a small buffer that gets flushed when full. This helps us avoid taking spinlocks when working with CA.
 */
#define REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE         2

/*
 * Stripped down version of service port's string name. This is to avoid overwhelming CA's dynamic memory allocation.
 */
#define CA_MACH_SERVICE_PORT_NAME_LEN                   86

struct reply_port_semantics_violations_rb_entry {
	char proc_name[CA_PROCNAME_LEN];
	char service_name[CA_MACH_SERVICE_PORT_NAME_LEN];
	char team_id[CA_TEAMID_MAX_LEN];
	char signing_id[CA_SIGNINGID_MAX_LEN];
	int  reply_port_semantics_violation;
	int  sw_platform;
	int  msgh_id;
	int  sdk;
};
struct reply_port_semantics_violations_rb_entry reply_port_semantics_violations_rb[REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE];
static uint8_t reply_port_semantics_violations_rb_index = 0;

LCK_GRP_DECLARE(reply_port_telemetry_lock_grp, "reply_port_telemetry_lock_grp");
LCK_SPIN_DECLARE(reply_port_telemetry_lock, &reply_port_telemetry_lock_grp);

/* Telemetry: report back the process name violating reply port semantics */
CA_EVENT(reply_port_semantics_violations,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name,
    CA_STATIC_STRING(CA_MACH_SERVICE_PORT_NAME_LEN), service_name,
    CA_STATIC_STRING(CA_TEAMID_MAX_LEN), team_id,
    CA_STATIC_STRING(CA_SIGNINGID_MAX_LEN), signing_id,
    CA_INT, reply_port_semantics_violation);

static void
send_reply_port_telemetry(
	const struct reply_port_semantics_violations_rb_entry *entry)
{
	ca_event_t ca_event = CA_EVENT_ALLOCATE_FLAGS(reply_port_semantics_violations, Z_NOWAIT);
	if (ca_event) {
		CA_EVENT_TYPE(reply_port_semantics_violations) * event = ca_event->data;

		strlcpy(event->service_name, entry->service_name, CA_MACH_SERVICE_PORT_NAME_LEN);
		strlcpy(event->proc_name, entry->proc_name, CA_PROCNAME_LEN);
		strlcpy(event->team_id, entry->team_id, CA_TEAMID_MAX_LEN);
		strlcpy(event->signing_id, entry->signing_id, CA_SIGNINGID_MAX_LEN);
		event->reply_port_semantics_violation = entry->reply_port_semantics_violation;

		CA_EVENT_SEND(ca_event);
	}
}

/* Routine: flush_reply_port_semantics_violations_telemetry
 * Conditions:
 *              Assumes the reply_port_telemetry_lock is held.
 *              Unlocks it before returning.
 */
static void
flush_reply_port_semantics_violations_telemetry(void)
{
	struct reply_port_semantics_violations_rb_entry local_rb[REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE];
	uint8_t local_rb_index = 0;

	if (__improbable(reply_port_semantics_violations_rb_index > REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE)) {
		panic("Invalid reply port semantics violations buffer index %d > %d",
		    reply_port_semantics_violations_rb_index, REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE);
	}

	/*
	 * We operate on local copy of telemetry buffer because CA framework relies on successfully
	 * allocating zalloc memory. It can not do that if we are accessing the shared buffer
	 * with spin locks held.
	 */
	while (local_rb_index != reply_port_semantics_violations_rb_index) {
		local_rb[local_rb_index] = reply_port_semantics_violations_rb[local_rb_index];
		local_rb_index++;
	}

	lck_spin_unlock(&reply_port_telemetry_lock);

	while (local_rb_index > 0) {
		struct reply_port_semantics_violations_rb_entry *entry = &local_rb[--local_rb_index];

		send_reply_port_telemetry(entry);
	}

	/*
	 * Finally call out the buffer as empty. This is also a sort of rate limiting mechanisms for the events.
	 * Events will get dropped until the buffer is not fully flushed.
	 */
	lck_spin_lock(&reply_port_telemetry_lock);
	reply_port_semantics_violations_rb_index = 0;
}

void
stash_reply_port_semantics_violations_telemetry(
	mach_service_port_info_t sp_info,
	int                     reply_port_semantics_violation,
	int                     msgh_id)
{
	struct reply_port_semantics_violations_rb_entry *entry;

	task_t task = current_task_early();
	if (task) {
		struct proc_ro *pro = current_thread_ro()->tro_proc_ro;
		uint32_t platform = pro->p_platform_data.p_platform;
		uint32_t sdk = pro->p_platform_data.p_sdk;
		char *proc_name = (char *) "unknown";
#ifdef MACH_BSD
		proc_name = proc_name_address(get_bsdtask_info(task));
#endif /* MACH_BSD */
		const char *team_id = csproc_get_identity(current_proc());
		const char *signing_id = csproc_get_teamid(current_proc());
		char *service_name = (char *) "unknown";
		if (sp_info) {
			service_name = sp_info->mspi_string_name;
		}

		lck_spin_lock(&reply_port_telemetry_lock);

		if (reply_port_semantics_violations_rb_index >= REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE) {
			/* Dropping the event since buffer is full. */
			lck_spin_unlock(&reply_port_telemetry_lock);
			return;
		}
		entry = &reply_port_semantics_violations_rb[reply_port_semantics_violations_rb_index++];
		strlcpy(entry->proc_name, proc_name, CA_PROCNAME_LEN);

		strlcpy(entry->service_name, service_name, CA_MACH_SERVICE_PORT_NAME_LEN);
		entry->reply_port_semantics_violation = reply_port_semantics_violation;
		if (team_id) {
			strlcpy(entry->team_id, team_id, CA_TEAMID_MAX_LEN);
		}

		if (signing_id) {
			strlcpy(entry->signing_id, signing_id, CA_SIGNINGID_MAX_LEN);
		}
		entry->msgh_id = msgh_id;
		entry->sw_platform = platform;
		entry->sdk = sdk;
	}

	if (reply_port_semantics_violations_rb_index == REPLY_PORT_SEMANTICS_VIOLATIONS_RB_SIZE) {
		flush_reply_port_semantics_violations_telemetry();
	}

	lck_spin_unlock(&reply_port_telemetry_lock);
}

void
send_prp_telemetry(int msgh_id)
{
	if (csproc_hardened_runtime(current_proc())) {
		stash_reply_port_semantics_violations_telemetry(NULL, MRP_HARDENED_RUNTIME_VIOLATOR, msgh_id);
	} else {
		stash_reply_port_semantics_violations_telemetry(NULL, MRP_3P_VIOLATOR, msgh_id);
	}
}


#pragma mark MACH_SEND_MSG policies

mach_msg_return_t
ipc_validate_kmsg_header_schema_from_user(
	mach_msg_user_header_t *hdr __unused,
	mach_msg_size_t         dsc_count,
	mach_msg_option64_t     opts)
{
	if (opts & MACH64_SEND_KOBJECT_CALL) {
		if (dsc_count > IPC_KOBJECT_DESC_MAX) {
			return MACH_SEND_TOO_LARGE;
		}
	}

	return MACH_MSG_SUCCESS;
}

mach_msg_return_t
ipc_validate_kmsg_schema_from_user(
	mach_msg_header_t      *kdata,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     opts __unused)
{
	mach_msg_kbase_t *kbase = NULL;
	vm_size_t vm_size;

	if (kdata->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		kbase = mach_msg_header_to_kbase(kdata);
	}

	if (send_uctx->send_dsc_port_count > IPC_KMSG_MAX_OOL_PORT_COUNT) {
		return MACH_SEND_TOO_LARGE;
	}

	if (os_add_overflow(send_uctx->send_dsc_vm_size,
	    send_uctx->send_dsc_port_count * sizeof(mach_port_t), &vm_size)) {
		return MACH_SEND_TOO_LARGE;
	}
	if (vm_size > ipc_kmsg_max_vm_space) {
		return MACH_MSG_VM_KERNEL;
	}

	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
ipc_filter_kmsg_header_from_user(
	mach_msg_header_t      *hdr,
	mach_msg_option64_t     opts)
{
	static const uint32_t MACH_BOOTSTRAP_PORT_MSG_ID_MASK = ((1u << 24) - 1);

	mach_msg_filter_id fid = 0;
	mach_port_t remote_port = hdr->msgh_remote_port;
	mach_msg_id_t msg_id = hdr->msgh_id;
	ipc_service_port_label_t label = NULL;
	void *sblabel = NULL;

	if (!ip_enforce_msg_filtering(remote_port)) {
		return MACH_MSG_SUCCESS;
	}

	ip_mq_lock(remote_port);
	if (!ip_active(remote_port)) {
		/* nothing to do */
	} else if (remote_port->ip_service_port) {
		label   = remote_port->ip_splabel;
		sblabel = label->ispl_sblabel;

		/*
		 * Mask the top byte for messages sent to launchd's bootstrap port.
		 * Filter any messages with domain 0 (as they correspond to MIG
		 * based messages)
		 */
		if (ipc_service_port_label_is_bootstrap_port(label)) {
			if ((msg_id & ~MACH_BOOTSTRAP_PORT_MSG_ID_MASK) == 0) {
				ip_mq_unlock(remote_port);
				goto filtered_msg;
			}
			msg_id = msg_id & MACH_BOOTSTRAP_PORT_MSG_ID_MASK;
		}
	} else {
		assert(!ip_is_kolabeled(remote_port));
		/* Connection ports can also have send-side message filters */
		sblabel = remote_port->ip_splabel;
	}
	if (sblabel) {
		mach_msg_filter_retain_sblabel_callback(sblabel);
	}
	ip_mq_unlock(remote_port);

	if (sblabel && !mach_msg_fetch_filter_policy(sblabel, msg_id, &fid)) {
		goto filtered_msg;
	}
	return MACH_MSG_SUCCESS;

filtered_msg:
	if ((opts & MACH64_POLICY_FILTER_NON_FATAL) == 0) {
		mach_port_name_t dest_name = CAST_MACH_PORT_TO_NAME(hdr->msgh_remote_port);

		mach_port_guard_exception(dest_name, 0, 0, kGUARD_EXC_MSG_FILTERED);
	}
	return MACH_SEND_MSG_FILTERED;
}

static bool
ipc_policy_allow_send_only_kobject_calls(void)
{
	struct proc_ro *pro = current_thread_ro()->tro_proc_ro;
	uint32_t sdk = pro->p_platform_data.p_sdk;
	uint32_t sdk_major = sdk >> 16;

	switch (pro->p_platform_data.p_platform) {
	case PLATFORM_IOS:
	case PLATFORM_MACCATALYST:
	case PLATFORM_TVOS:
		if (sdk == 0 || sdk_major > 17) {
			return false;
		}
		return true;
	case PLATFORM_MACOS:
		if (sdk == 0 || sdk_major > 14) {
			return false;
		}
		return true;
	case PLATFORM_WATCHOS:
		if (sdk == 0 || sdk_major > 10) {
			return false;
		}
		return true;
	default:
		return false;
	}
}

static mach_msg_return_t
ipc_validate_kmsg_dest_from_user(
	mach_msg_header_t      *hdr,
	ipc_port_t              port,
	mach_msg_option64_t     opts)
{
	/*
	 * This is a _user_ message via mach_msg2_trap()。
	 *
	 * To curb kobject port/message queue confusion and improve control flow
	 * integrity, mach_msg2_trap() invocations mandate the use of either
	 * MACH64_SEND_KOBJECT_CALL or MACH64_SEND_MQ_CALL and that the flag
	 * matches the underlying port type. (unless the call is from a simulator,
	 * since old simulators keep using mach_msg() in all cases indiscriminatingly.)
	 *
	 * Since:
	 *     (1) We make sure to always pass either MACH64_SEND_MQ_CALL or
	 *         MACH64_SEND_KOBJECT_CALL bit at all sites outside simulators
	 *         (checked by mach_msg2_trap());
	 *     (2) We checked in mach_msg2_trap() that _exactly_ one of the three bits is set.
	 *
	 * CFI check cannot be bypassed by simply setting MACH64_SEND_ANY.
	 */
#if XNU_TARGET_OS_OSX
	if (opts & MACH64_SEND_ANY) {
		return MACH_MSG_SUCCESS;
	}
#endif /* XNU_TARGET_OS_OSX */

	if (ip_is_kobject(port)) {
		natural_t kotype = ip_kotype(port);

		if (__improbable(kotype == IKOT_TIMER)) {
#if XNU_TARGET_OS_OSX
			if (__improbable(opts & MACH64_POLICY_HARDENED)) {
				return MACH_SEND_INVALID_OPTIONS;
			}
			/*
			 * For bincompat, let's still allow user messages to timer port, but
			 * force MACH64_SEND_MQ_CALL flag for memory segregation.
			 */
			if (__improbable(!(opts & MACH64_SEND_MQ_CALL))) {
				return MACH_SEND_INVALID_OPTIONS;
			}
#else
			return MACH_SEND_INVALID_OPTIONS;
#endif
		} else if (kotype == IKOT_UEXT_OBJECT) {
			if (__improbable(!(opts & MACH64_SEND_DK_CALL))) {
				return MACH_SEND_INVALID_OPTIONS;
			}
		} else {
			/* Otherwise, caller must set MACH64_SEND_KOBJECT_CALL. */
			if (__improbable(!(opts & MACH64_SEND_KOBJECT_CALL))) {
				return MACH_SEND_INVALID_OPTIONS;
			}

			/* kobject calls must be a combined send/receive */
			if (__improbable((opts & MACH64_RCV_MSG) == 0)) {
				if ((opts & MACH64_POLICY_HARDENED) ||
				    IP_VALID(hdr->msgh_local_port) ||
				    !ipc_policy_allow_send_only_kobject_calls()) {
					return MACH_SEND_INVALID_OPTIONS;
				}
			}
		}
#if CONFIG_CSR
	} else if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) == 0) {
		/*
		 * Allow MACH64_SEND_KOBJECT_CALL flag to message queues
		 * when SIP is off (for Mach-on-Mach emulation).
		 */
#endif /* CONFIG_CSR */
	} else {
		/* If destination is a message queue, caller must set MACH64_SEND_MQ_CALL */
		if (__improbable(!(opts & MACH64_SEND_MQ_CALL))) {
			return MACH_SEND_INVALID_OPTIONS;
		}
	}

	return MACH_MSG_SUCCESS;
}

mach_msg_return_t
ipc_validate_kmsg_header_from_user(
	mach_msg_header_t      *hdr,
	mach_msg_send_uctx_t   *send_uctx,
	mach_msg_option64_t     opts)
{
	ipc_port_t dest_port = hdr->msgh_remote_port;
	mach_msg_return_t mr = KERN_SUCCESS;

	if (opts & MACH64_MACH_MSG2) {
		mr = ipc_validate_kmsg_dest_from_user(hdr, dest_port, opts);
		if (mr != MACH_MSG_SUCCESS) {
			goto out;
		}
	}

	/*
	 * Check if dest is a no-grant port; Since this bit is set only on
	 * port construction and cannot be unset later, we can peek at the
	 * bit without paying the cost of locking the port.
	 */
	if (send_uctx->send_dsc_port_count && dest_port->ip_no_grant) {
		mr = MACH_SEND_NO_GRANT_DEST;
		goto out;
	}

	/*
	 * Evaluate message filtering if the sender is filtered.
	 */
	if ((opts & MACH64_POLICY_FILTER_MSG) &&
	    mach_msg_filter_at_least(MACH_MSG_FILTER_CALLBACKS_VERSION_1)) {
		mr = ipc_filter_kmsg_header_from_user(hdr, opts);
		if (mr != MACH_MSG_SUCCESS) {
			goto out;
		}
	}

out:
	if (mr == MACH_SEND_INVALID_OPTIONS) {
		mach_port_guard_exception(0, 0, 0, kGUARD_EXC_INVALID_OPTIONS);
	}
	return mr;
}
