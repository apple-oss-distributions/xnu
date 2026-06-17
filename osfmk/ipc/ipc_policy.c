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
#include <mach/mk_timer.h>
#include <mach/notify.h>

#include <kern/assert.h>
#include <kern/backtrace.h>
#include <kern/exc_guard.h>
#include <kern/kcdata.h>
#include <kern/telemetry.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/kern_types.h>
#include <kern/mach_filter.h>
#include <kern/task.h>
#include <kern/ux_handler.h> /* is_ux_handler_port() */

#include <vm/vm_map_xnu.h> /* current_map() */
#include <vm/vm_protos.h> /* current_proc() */

#include <kdp/kdp_dyld.h> /* dyld_all_image_infos structures */

#include <ipc/ipc_policy.h>
#include <ipc/ipc_service_port.h>
#include <ipc/port.h>

#if CONFIG_CSR
#include <sys/csr.h>
#endif
#include <sys/codesign.h>
#include <sys/proc_ro.h>
#include <sys/reason.h>

#include <libkern/coreanalytics/coreanalytics.h>

extern bool proc_is_simulated(struct proc *);
extern char *proc_name_address(struct proc *p);
extern int  exit_with_guard_exception(
	struct proc            *p,
	mach_exception_data_type_t code,
	mach_exception_data_type_t subcode);

#pragma mark policy tunables

extern const vm_size_t  ipc_kmsg_max_vm_space;

#if IPC_HAS_LEGACY_MACH_MSG_TRAP
#if DEVELOPMENT || DEBUG
static TUNABLE(bool, allow_legacy_mach_msg, "allow_legacy_mach_msg", false);
#endif /* DEVELOPMENT || DEBUG */
#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */

/* Note: Consider Developer Mode when changing the default. */
TUNABLE(ipc_control_port_options_t, ipc_control_port_options,
    "ipc_control_port_options",
    ICP_OPTIONS_IMMOVABLE_1P_HARD |
    ICP_OPTIONS_PINNED_1P_HARD |
#if !XNU_TARGET_OS_OSX
    ICP_OPTIONS_IMMOVABLE_3P_HARD |
#endif
    ICP_OPTIONS_PINNED_3P_SOFT);

/* The bootarg to disable ALL ipc policy violation telemetry */
TUNABLE(bool, ipcpv_telemetry_enabled, "-ipcpv_telemetry_enabled", true);

/* Enables reply port/voucher/persona debugging code */
TUNABLE(bool, enforce_strict_reply, "-enforce_strict_reply", false);

/* At-desk toggle for OOL port array restrictions */
TUNABLE(bool, ool_port_array_enforced, "ool_port_array_enforced", true);

TUNABLE(bool, cv_notif_port_required_enforced, "cv_notif_port_required_enforced", false);

#pragma mark policy options

inline bool
ip_has_reply_port_semantics(ipc_port_t port)
{
	return port->ip_enforce_reply_semantics ||
	       ipc_policy(port)->pol_enforce_reply_semantics;
}

ipc_space_policy_t
ipc_policy_for_task(task_t task)
{
#if XNU_TARGET_OS_OSX
	struct proc *proc = get_bsdtask_info(task);
#endif /* XNU_TARGET_OS_OSX */
	ipc_space_policy_t policy = IPC_SPACE_POLICY_DEFAULT;
	uint32_t ro_flags;

	if (task == kernel_task) {
		return policy | IPC_SPACE_POLICY_KERNEL;
	}

	ro_flags = task_ro_flags_get(task);
	if (ro_flags & TFRO_PLATFORM) {
		policy |= IPC_SPACE_POLICY_PLATFORM;
		policy |= IPC_POLICY_ENHANCED_VMAX;
	}

	if (task_get_platform_restrictions_version(task) >= 3) {
		policy |= IPC_POLICY_ENHANCED_V3;
	} else if (task_get_platform_restrictions_version(task) == 2) {
		policy |= IPC_POLICY_ENHANCED_V2;
	} else if (task_get_platform_restrictions_version(task) == 1) {
		policy |= IPC_POLICY_ENHANCED_V1;
#if XNU_TARGET_OS_OSX
	} else if (proc && csproc_hardened_runtime(proc)) {
		policy |= IPC_POLICY_ENHANCED_V0;
#endif /* XNU_TARGET_OS_OSX */
	}

#if XNU_TARGET_OS_OSX
	if (task_opted_out_mach_hardening(task)) {
		policy |= IPC_SPACE_POLICY_OPTED_OUT;
	}
#endif /* XNU_TARGET_OS_OSX */

	if (task_has_ipc_containment_vessel(task)) {
		policy |= IPC_SPACE_POLICY_CONTAINED;
	}

	/*
	 * policy modifiers
	 */
#if XNU_TARGET_OS_OSX
	if (proc && proc_is_simulated(proc)) {
		policy |= IPC_SPACE_POLICY_SIMULATED;
	}
#endif
#if CONFIG_ROSETTA
	if (task_is_translated(task)) {
		policy |= IPC_SPACE_POLICY_TRANSLATED;
	}
#endif

	return policy;
}


inline ipc_space_policy_t
ipc_convert_msg_options_to_space(mach_msg_option64_t opts)
{
	return opts >> MACH64_POLICY_SHIFT;
}

mach_msg_option64_t
ipc_current_msg_options(
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
	{
		/*
		 * mach_msg_option64_t can't use IPC_SPACE_POLICY_BASE(),
		 * check using this MACH64_POLICY_SHIFT is legitimate.
		 */
#define verify_policy_enum(name) \
	static_assert(IPC_SPACE_POLICY_ ## name == \
	    MACH64_POLICY_ ## name >> MACH64_POLICY_SHIFT)

		verify_policy_enum(DEFAULT);
		verify_policy_enum(ENHANCED);
		verify_policy_enum(PLATFORM);
		verify_policy_enum(KERNEL);
		verify_policy_enum(SIMULATED);
		verify_policy_enum(TRANSLATED);
		verify_policy_enum(OPTED_OUT);
		verify_policy_enum(ENHANCED_V0);
		verify_policy_enum(ENHANCED_V1);
		verify_policy_enum(ENHANCED_V2);
		verify_policy_enum(ENHANCED_V3);
		verify_policy_enum(ENHANCED_VERSION_MASK);
		verify_policy_enum(MASK);

#undef verify_policy_enum
	}

	opts |= (uint64_t)ipc_space_policy(task->itk_space) << MACH64_POLICY_SHIFT;

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

	mach_port_guard_exception(0, opts, kGUARD_EXC_INVALID_OPTIONS);
	if (opts & MACH64_MACH_MSG2) {
		return MACH_SEND_INVALID_OPTIONS;
	}
	return KERN_NOT_SUPPORTED;
}

#pragma mark helpers

__mockable bool
ipc_should_apply_policy(
	const ipc_space_policy_t current_policy,
	const ipc_space_policy_t requested_level)
{
	/*
	 * Version bits (IPC_SPACE_POLICY_ENHANCED_VERSION_MASK) are only
	 * meaningful inside the ENHANCED branch below. A caller that passes
	 * version bits without IPC_SPACE_POLICY_ENHANCED (e.g. accidentally
	 * using IPC_SPACE_POLICY_ENHANCED_V1 instead of IPC_POLICY_ENHANCED_V1)
	 * will silently fall through to the bitwise fallback and return the
	 * wrong result.
	 */
	assert(!(requested_level & IPC_SPACE_POLICY_ENHANCED_VERSION_MASK) ||
	    (requested_level & IPC_SPACE_POLICY_ENHANCED));

	/*
	 * IPC_SPACE_POLICY_DEFAULT may be passed alone as a requested_level
	 * (meaning "should this space be opted out"), but must not
	 * be combined with other bits. Mixing it with specific policy flags is
	 * always a caller bug since it always returns true unless opted out
	 */
	assert(!(requested_level & IPC_SPACE_POLICY_DEFAULT) || requested_level == IPC_SPACE_POLICY_DEFAULT);

	/* Do not apply security policies on these binaries to avoid bincompat regression */
	if ((current_policy & IPC_SPACE_POLICY_SIMULATED) ||
	    (current_policy & IPC_SPACE_POLICY_OPTED_OUT) ||
	    (current_policy & IPC_SPACE_POLICY_TRANSLATED)) {
		return false;
	}

	/* Containment vessels take precedent */
	if (requested_level & IPC_SPACE_POLICY_CONTAINED) {
		return current_policy & IPC_SPACE_POLICY_CONTAINED;
	}

	/* Check versioning for applying platform restrictions policy */
	if (requested_level & current_policy & IPC_SPACE_POLICY_ENHANCED) {
		/* Platform is always opted into platform restrictions */
		if (current_policy & IPC_SPACE_POLICY_PLATFORM) {
			return true;
		}

		const ipc_space_policy_t requested_version = requested_level & IPC_SPACE_POLICY_ENHANCED_VERSION_MASK;
		const ipc_space_policy_t current_es_version = current_policy & IPC_SPACE_POLICY_ENHANCED_VERSION_MASK;
		assert(requested_version != 0);
		return requested_version <= current_es_version;
	}

	return current_policy & requested_level;
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
	 * allow for a hardcoded list of MIG calls to XNU to go through
	 * for macOS apps linked against an SDK older than 12.x.
	 */
	switch (platform) {
	case PLATFORM_MACOS:
		if (sdk == 0 || sdk_major > 12) {
			return false;
		}
		break;
	default:
		/* disallow for any non-macOS for platform */
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
	/* equivalent to ENHANCED_V0 */
	if ((opts & MACH64_POLICY_ENHANCED) == 0) {
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

	mach_port_guard_exception(msgid, opts, kGUARD_EXC_INVALID_OPTIONS);
	/*
	 * this should be MACH_SEND_INVALID_OPTIONS,
	 * but this is a new mach_msg2 error only.
	 */
	return KERN_NOT_SUPPORTED;
}


#endif /* IPC_HAS_LEGACY_MACH_MSG_TRAP */

#pragma mark ipc policy telemetry

#define IPC_POLICY_BACKTRACE_FRAME_COUNT 10
/*
 * process UUID data: 52 byte
 * dyld UUID data: max dylibs 4 x 52 byte
 * backtrace: 10 frame x 8 bytes per frame
 */
#define IPC_POLICY_BACKTRACE_AND_SYM_LEN 340
#define IPC_POLICY_HEX_ADDR_STR_LEN 19 /* "0x" + 16 hex digits + null */
#define IPC_POLICY_UUID_STR_LEN 37     /* "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" + null */

CA_EVENT(ipc_sec_policy_violation,
    CA_STATIC_STRING(CA_PROCNAME_LEN), proc_name,
    CA_STATIC_STRING(CA_MACH_SERVICE_PORT_NAME_LEN), service_name,
    CA_STATIC_STRING(CA_TEAMID_MAX_LEN), team_id,
    CA_STATIC_STRING(CA_SIGNINGID_MAX_LEN), signing_id,
    CA_INT, ipc_sec_policy_violation_id,
    CA_INT, aux_data,
    CA_STATIC_STRING(IPC_POLICY_BACKTRACE_AND_SYM_LEN), user_backtrace,
    CA_STATIC_STRING(IPC_POLICY_HEX_ADDR_STR_LEN), shared_cache_base,
    CA_STATIC_STRING(IPC_POLICY_HEX_ADDR_STR_LEN), shared_cache_slide,
    CA_STATIC_STRING(IPC_POLICY_UUID_STR_LEN), shared_cache_uuid,
    CA_STATIC_STRING(IPC_POLICY_HEX_ADDR_STR_LEN), main_exec_load_addr,
    CA_STATIC_STRING(IPC_POLICY_HEX_ADDR_STR_LEN), main_exec_slide,
    CA_STATIC_STRING(IPC_POLICY_UUID_STR_LEN), main_exec_uuid);

static void
ipc_sec_commit_policy_violation_to_ca(
	ipc_sec_policy_t violation_id,
	const char proc_name[CA_PROCNAME_LEN],
	const char service_name[CA_MACH_SERVICE_PORT_NAME_LEN],
	const char team_id[CA_TEAMID_MAX_LEN],
	const char signing_id[CA_SIGNINGID_MAX_LEN],
	int aux_data,
	uintptr_t *user_bt_frames,
	unsigned int user_bt_count,
	const char *shared_cache_base,
	const char *shared_cache_slide,
	const char *shared_cache_uuid,
	const char *main_exec_load_addr,
	const char *main_exec_slide,
	const char *main_exec_uuid)
{
	ca_event_t ca_event = CA_EVENT_ALLOCATE_FLAGS(ipc_sec_policy_violation, Z_WAITOK);
	if (!ca_event) {
		/* How did this happen?! We passed Z_WAITOK... */
		return;
	}

	CA_EVENT_TYPE(ipc_sec_policy_violation) * event = ca_event->data;

	event->ipc_sec_policy_violation_id = violation_id;
	if (service_name) {
		strlcpy(event->service_name, service_name, CA_MACH_SERVICE_PORT_NAME_LEN);
	}
	if (proc_name) {
		strlcpy(event->proc_name, proc_name, CA_PROCNAME_LEN);
	}
	if (team_id) {
		strlcpy(event->team_id, team_id, CA_TEAMID_MAX_LEN);
	}
	if (signing_id) {
		strlcpy(event->signing_id, signing_id, CA_SIGNINGID_MAX_LEN);
	}
	event->aux_data = aux_data;

	/* Encode user backtrace as raw addresses for CoreAnalytics */
	size_t offset = 0;
	for (unsigned int i = 0; i < user_bt_count && offset < sizeof(event->user_backtrace); i++) {
		offset += snprintf(event->user_backtrace + offset,
		    sizeof(event->user_backtrace) - offset,
		    "0x%lx\n", user_bt_frames[i]);
	}

	/* Copy shared cache base, slide and UUID for symbolication */
	if (shared_cache_base) {
		strlcpy(event->shared_cache_base, shared_cache_base, IPC_POLICY_HEX_ADDR_STR_LEN);
	}
	if (shared_cache_slide) {
		strlcpy(event->shared_cache_slide, shared_cache_slide, IPC_POLICY_HEX_ADDR_STR_LEN);
	}
	if (shared_cache_uuid) {
		strlcpy(event->shared_cache_uuid, shared_cache_uuid, IPC_POLICY_UUID_STR_LEN);
	}

	/* Copy main executable load address, slide and UUID for symbolication */
	if (main_exec_load_addr) {
		strlcpy(event->main_exec_load_addr, main_exec_load_addr, IPC_POLICY_HEX_ADDR_STR_LEN);
	}
	if (main_exec_slide) {
		strlcpy(event->main_exec_slide, main_exec_slide, IPC_POLICY_HEX_ADDR_STR_LEN);
	}
	if (main_exec_uuid) {
		strlcpy(event->main_exec_uuid, main_exec_uuid, IPC_POLICY_UUID_STR_LEN);
	}

	CA_EVENT_SEND(ca_event);
}

/*!
 * @brief
 * Checks that this message conforms to reply port policies, which are:
 * 1. IOT_REPLY_PORT's must be make-send-once disposition
 * 2. You must use an IOT_REPLY_PORT (or weak variant) if the dest_port requires it
 *
 * @param reply_port    the message local/reply port
 * @param dest_port     the message remote/dest port
 *
 * @returns
 * - MACH_MSG_SUCCESS if there is no violation in the security policy for this mach msg
 * - a contextual error code otherwise
 */
__static_testable mach_msg_return_t
ipc_validate_local_port(
	mach_port_t         reply_port,
	mach_port_t         dest_port,
	mach_msg_option64_t opts)
{
	ipc_sec_policy_t policy_violation = IPC_SEC_POLICY_NONE;
	uint64_t exc_payload = 0;

	assert(IP_VALID(dest_port));

	/* An empty reply port, or an inactive reply port / dest port violates nothing */
	if (!IP_VALID(reply_port) || !ip_active(reply_port) || !ip_active(dest_port)) {
		return MACH_MSG_SUCCESS;
	}

	if (!ip_has_reply_port_semantics(dest_port)) {
		return MACH_MSG_SUCCESS;
	}

	/* skip translated and simulated process */
	ipc_space_policy_t pol = ipc_convert_msg_options_to_space(opts);
	if (!ipc_should_apply_policy((pol), IPC_SPACE_POLICY_DEFAULT)) {
		return MACH_MSG_SUCCESS;
	}

	if (ip_is_kobject(dest_port)) {
		/* kobject enforcement */
		if (ipc_should_apply_policy(pol, IPC_POLICY_ENHANCED_V1) &&
		    !ip_is_reply_port(reply_port)) {
			policy_violation = IPC_SEC_POLICY_REQUIRE_REPLY_PORT_SEMANTICS_KOBJECT;
		}
	} else if (ip_is_bootstrap_port(dest_port)) {
		/* bootstrap port defense */
		if (ipc_should_apply_policy(pol, IPC_POLICY_ENHANCED_V2) &&
		    !ip_is_reply_port(reply_port) &&
		    !ip_is_weak_reply_port(reply_port)) {
			policy_violation = IPC_SEC_POLICY_REQUIRE_REPLY_PORT_SEMANTICS_BOOTSTRAP_PORT;
			exc_payload = 1;
		}
	} else {
		/* regular enforcement */
		if (!ip_is_reply_port(reply_port) &&
		    !ip_is_weak_reply_port(reply_port)) {
			policy_violation = IPC_SEC_POLICY_REQUIRE_REPLY_PORT_SEMANTICS_SERVICE_PORT;
		}
	}

	if (policy_violation != IPC_SEC_POLICY_NONE) {
		ipc_triage_policy_violation_and_expect_deny(
			policy_violation,
			current_space(),
			ip_get_receiver_name(dest_port),
			exc_payload,
			IPC_PORT_NULL,
			0
			);
		return MACH_SEND_INVALID_REPLY;
	}

	return MACH_MSG_SUCCESS;
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

	/*
	 * Collect telemetry when we notice an especially high inline port descriptor
	 * count, so we can make data-driven decisions in future about what a sensible
	 * limit might be.
	 */
	if (send_uctx->send_dsc_inline_port_count >= IPC_KMSG_INLINE_PORT_DESCRIPTOR_SOFT_LIMIT) {
		ipc_triage_policy_violation_and_expect_continue(
			IPC_SEC_POLICY_RESTRICT_INLINE_PORT_DESCRIPTORS,
			current_space(),
			0,
			send_uctx->send_dsc_inline_port_count,
			IP_NULL,
			send_uctx->send_dsc_inline_port_count
			);
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
	mach_port_t             dport,
	mach_msg_option64_t     opts)
{
	static const uint32_t MACH_BOOTSTRAP_PORT_MSG_ID_MASK = ((1u << 24) - 1);

	mach_msg_filter_id fid = 0;
	ipc_object_label_t dlabel;
	mach_msg_id_t msg_id = hdr->msgh_id;
	struct ipc_conn_port_label *sblabel = NULL;

	dlabel = ip_mq_lock_label_get(dport);

	if (io_state_active(dlabel.io_state) && dlabel.io_filtered) {
		switch (dlabel.io_type) {
		case IOT_BOOTSTRAP_PORT:
			/*
			 * Mask the top byte for messages sent to launchd's bootstrap port.
			 * Filter any messages with domain 0 (as they correspond to MIG
			 * based messages)
			 */
			if ((msg_id & ~MACH_BOOTSTRAP_PORT_MSG_ID_MASK) == 0) {
				ip_mq_unlock_label_put(dport, &dlabel);
				goto filtered_msg;
			}
			msg_id = msg_id & MACH_BOOTSTRAP_PORT_MSG_ID_MASK;
			sblabel = dlabel.iol_bootstrap->ispl_sblabel;
			break;

		case IOT_SERVICE_PORT:
		case IOT_WEAK_SERVICE_PORT:
			sblabel = dlabel.iol_service->ispl_sblabel;
			break;

		case IOT_CONNECTION_PORT:
			/* Connection ports can also have send-side message filters */
			sblabel = dlabel.iol_connection;
			break;

		default:
			break;
		}
	}
	if (sblabel) {
		mach_msg_filter_retain_sblabel_callback(sblabel);
	}

	ip_mq_unlock_label_put(dport, &dlabel);

	if (sblabel && !mach_msg_fetch_filter_policy(sblabel, msg_id, &fid)) {
		goto filtered_msg;
	}
	return MACH_MSG_SUCCESS;

filtered_msg:
	if ((opts & MACH64_POLICY_FILTER_NON_FATAL) == 0) {
		mach_port_name_t dest_name = CAST_MACH_PORT_TO_NAME(hdr->msgh_remote_port);

		mach_port_guard_exception(dest_name, hdr->msgh_id,
		    kGUARD_EXC_MSG_FILTERED);
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

	natural_t otype = ip_type(port);
	if (otype == IOT_TIMER_PORT) {
#if XNU_TARGET_OS_OSX
		if (__improbable(opts & MACH64_POLICY_ENHANCED)) {
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
	} else if (io_is_kobject_type(otype)) {
		if (otype == IKOT_UEXT_OBJECT) {
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
				if ((opts & MACH64_POLICY_ENHANCED) ||
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
	ipc_port_t reply_port = hdr->msgh_local_port;
	mach_msg_return_t mr = MACH_MSG_SUCCESS;
	ipc_space_policy_t current_policy;

	if (opts & MACH64_MACH_MSG2) {
		mr = ipc_validate_kmsg_dest_from_user(hdr, dest_port, opts);
		if (mr != MACH_MSG_SUCCESS) {
			goto out;
		}
	}

	/*
	 * For enhanced v2 binaries, enforce two OOL port array restrictions:
	 *     - the receive right has to be of a type that explicitly
	 *       allows receiving that descriptor
	 *     - there could be no more than ONE single array in a kmsg
	 */
	current_policy = ipc_convert_msg_options_to_space(opts);
	if (ipc_sec_is_policy_enforced(IPC_SEC_POLICY_RESTRICT_OOL_PORT_ARRAYS) &&
	    send_uctx->send_dsc_port_arrays_count &&
	    ipc_should_apply_policy(current_policy, IPC_POLICY_ENHANCED_V2)) {
		if (!ip_is_port_array_allowed(dest_port)) {
			ipc_triage_policy_violation_and_expect_deny(
				IPC_SEC_POLICY_RESTRICT_OOL_PORT_ARRAYS,
				NULL,
				current_policy,
				MPG_PAYLOAD(MPG_FLAGS_INVALID_OPTIONS_OOL_RIGHT, ip_type(dest_port)),
				dest_port,
				0
				);
			return MACH_SEND_INVALID_OPTIONS;
		}

		if (send_uctx->send_dsc_port_arrays_count > 1) {
			ipc_triage_policy_violation_and_expect_deny(
				IPC_SEC_POLICY_RESTRICT_OOL_PORT_ARRAYS,
				NULL,
				current_policy,
				MPG_PAYLOAD(MPG_FLAGS_INVALID_OPTIONS_OOL_ARRAYS, send_uctx->send_dsc_port_arrays_count),
				dest_port,
				0
				);
			return MACH_SEND_INVALID_OPTIONS;
		}
	}

	/*
	 * Ensure that the reply field follows our security policies,
	 * including IOT_REPLY_PORT requirements
	 */
	mr = ipc_validate_local_port(reply_port, dest_port, opts);
	if (mr != MACH_MSG_SUCCESS) {
		goto out;
	}

	/*
	 * Evaluate message filtering if the sender is filtered.
	 */
	if ((opts & MACH64_POLICY_FILTER_MSG) &&
	    mach_msg_filter_at_least(MACH_MSG_FILTER_CALLBACKS_VERSION_1) &&
	    ip_to_object(dest_port)->io_filtered) {
		mr = ipc_filter_kmsg_header_from_user(hdr, dest_port, opts);
		if (mr != MACH_MSG_SUCCESS) {
			goto out;
		}
	}

out:
	if (mr == MACH_SEND_INVALID_OPTIONS) {
		mach_port_guard_exception(0, opts, kGUARD_EXC_INVALID_OPTIONS);
	}
	return mr;
}

#pragma mark receive immovability

bool
ipc_move_receive_allowed(
	ipc_space_t             space,
	ipc_port_t              port,
	mach_port_name_t        name)
{
	ipc_space_policy_t policy = ipc_space_policy(space);
	/*
	 * Check for service port before immovability so the task crash
	 * with reason kGUARD_EXC_SERVICE_PORT_VIOLATION_FATAL
	 */
	if (ipc_sec_is_policy_enforced(IPC_SEC_POLICY_RESTRICT_MOVE_SERVICE_PORT) &&
	    ip_is_strong_service_port(port) &&
	    !task_is_initproc(space->is_task)) {
		ipc_triage_policy_violation_and_expect_deny(
			IPC_SEC_POLICY_RESTRICT_MOVE_SERVICE_PORT,
			space,
			0,
			name,
			port,
			0
			);
		return false;
	}

	if (ip_type(port) == IOT_WEAK_REPLY_PORT &&
	    ipc_should_apply_policy(policy, IPC_POLICY_ENHANCED_V2)) {
		ipc_triage_policy_violation_and_expect_continue(
			IPC_SEC_POLICY_RESTRICT_MOVE_WEAK_REPLY_PORT,
			space,
			name,
			0,
			port,
			0
			);
	}

	if (ip_type(port) == IOT_PORT &&
	    ipc_should_apply_policy(policy, IPC_SPACE_POLICY_CONTAINED)) {
		ipc_triage_policy_violation_and_expect_continue(
			IPC_SEC_POLICY_RESTRICT_MOVE_IOT_PORT,
			space,
			0,
			0,
			port,
			0
			);
	}

	if (ip_is_immovable_receive(port)) {
		mach_port_guard_exception(name, 0, kGUARD_EXC_IMMOVABLE);
		return false;
	}

	return true;
}

#pragma mark send immovability

__mockable
bool
ipc_should_mark_immovable_send(
	task_t curr_task,
	ipc_port_t port,
	ipc_object_label_t label)
{
	thread_t ctrl_thread = THREAD_NULL;
	task_t   ctrl_task   = TASK_NULL;

	/*
	 * task obtaining its own task control port is controlled by security policy
	 * see `task_set_ctrl_port_default`
	 * This must come first so that we avoid evaluating the kobject port before ipc_task_enable has run
	 */
	if (curr_task->itk_task_ports[TASK_FLAVOR_CONTROL] == port) {
		return task_is_immovable(curr_task);
	}

	switch (ip_type(port)) {
	case IKOT_TASK_CONTROL:
		ctrl_task = ipc_kobject_get_raw(port, IKOT_TASK_CONTROL);
		break;
	case IKOT_THREAD_CONTROL:
		ctrl_thread = ipc_kobject_get_raw(port, IKOT_THREAD_CONTROL);
		if (ctrl_thread) {
			ctrl_task = get_threadtask(ctrl_thread);
		}
		break;
	default:
		break;
	}

	/*
	 * task obtaining its own thread control port is controlled by security policy
	 * see `task_set_ctrl_port_default`
	 */
	if (ctrl_thread && curr_task == ctrl_task) {
		/*
		 * we cannot assert that the control port options for the task are set up
		 * yet because we may be copying out the thread control port during exec.
		 * This means that the first thread control port copyout will always be movable, but other
		 * copyouts will occur before userspace is allowed to run any code which will subsequently mark it
		 * as immovable if needed.
		 */
		return task_is_immovable_no_assert(curr_task);
	}

	/*
	 * all control ports obtained by another process are movable
	 * while the space is inactive (for corpses).
	 */
	if (ctrl_task && !is_active(ctrl_task->itk_space)) {
		assert(ctrl_task != curr_task);
		assert(ip_is_tt_control_port_type(label.io_type));
		return false;
	}

	/* special cases are handled, now we refer to the default policy */
	return !ipc_policy(label)->pol_movable_send;
}

/* requires: nothing locked, port is valid */
static bool
ip_is_currently_immovable_send(ipc_port_t port)
{
	ipc_object_label_t label = ipc_port_lock_label_get(port);
	bool port_is_immovable_send = ipc_should_mark_immovable_send(current_task(), port, label);
	ip_mq_unlock_label_put(port, &label);
	return port_is_immovable_send;
}

/* requires: nothing locked, port is valid */
bool
ipc_can_stash_naked_send(ipc_port_t port)
{
	return !IP_VALID(port) || !ip_is_currently_immovable_send(port);
}

#pragma mark entry init

void
ipc_entry_init(
	ipc_space_t         space,
	ipc_object_t        object,
	mach_port_type_t    type,
	ipc_entry_t         entry,
	mach_port_urefs_t   urefs,
	mach_port_name_t    name)
{
	/* object type can be deadname, port, or a portset */
	assert((type & MACH_PORT_TYPE_ALL_RIGHTS) == type);
	assert(type != MACH_PORT_TYPE_NONE);
	assert(urefs <= MACH_PORT_UREFS_MAX);
	assert(entry);

	if (object && (type & MACH_PORT_TYPE_SEND_RIGHTS)) {
		ipc_port_t port = ip_object_to_port(object);
		ipc_object_label_t label = ip_label_get(port);

		if (ipc_should_mark_immovable_send(space->is_task, port, label)) {
			entry->ie_bits |= IE_BITS_IMMOVABLE_SEND;
		}
		io_label_set_and_put(&port->ip_object, &label);
	}
	entry->ie_object = object;
	entry->ie_bits |= type | urefs;
	ipc_entry_modified(space, name, entry);
}

#pragma mark policy guard violations

void
mach_port_guard_exception(uint32_t target, uint64_t payload, unsigned reason)
{
	mach_exception_code_t code = 0;
	EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_MACH_PORT);
	EXC_GUARD_ENCODE_FLAVOR(code, reason);
	EXC_GUARD_ENCODE_TARGET(code, target);
	mach_exception_subcode_t subcode = (uint64_t)payload;
	thread_t t = current_thread();

	bool sticky = false;
	if (reason <= MAX_OPTIONAL_kGUARD_EXC_CODE &&
	    (get_threadtask(t)->task_exc_guard & TASK_EXC_GUARD_MP_FATAL)) {
		sticky = true;
	} else if (reason <= MAX_FATAL_kGUARD_EXC_CODE) {
		sticky = true;
	}
	thread_guard_violation(t, code, subcode, sticky);
}

void
mach_port_guard_exception_immovable(
	ipc_space_t             space,
	mach_port_name_t        name,
	mach_port_t             port,
	mach_msg_type_name_t    disp,
	__assert_only ipc_entry_t entry)
{
	if (space == current_space()) {
		assert(entry->ie_bits & IE_BITS_IMMOVABLE_SEND);
		assert(entry->ie_port == port);
		uint64_t payload = MPG_PAYLOAD(MPG_FLAGS_NONE, ip_type(port), disp);
		mach_port_guard_exception(name, payload, kGUARD_EXC_IMMOVABLE);
	}
}

void
mach_port_guard_exception_pinned(
	ipc_space_t             space,
	mach_port_name_t        name,
	uint64_t                payload)
{
	ipc_space_policy_t policy = ipc_space_policy(space);
	int guard;

	if (space != current_space()) {
		guard = kGUARD_EXC_NONE;
	} else if (policy &
	    (IPC_SPACE_POLICY_TRANSLATED | IPC_SPACE_POLICY_SIMULATED)) {
		guard = kGUARD_EXC_NONE;
	} else if (ipc_should_apply_policy(policy, IPC_POLICY_ENHANCED_V1)) {
		if (ipc_control_port_options & ICP_OPTIONS_PINNED_1P_HARD) {
			guard = kGUARD_EXC_MOD_REFS;
		} else if (ipc_control_port_options & ICP_OPTIONS_PINNED_1P_SOFT) {
			guard = kGUARD_EXC_MOD_REFS_NON_FATAL;
		} else {
			guard = kGUARD_EXC_NONE;
		}
	} else {
		if (ipc_control_port_options & ICP_OPTIONS_PINNED_3P_HARD) {
			guard = kGUARD_EXC_MOD_REFS;
		} else if (ipc_control_port_options & ICP_OPTIONS_PINNED_3P_SOFT) {
			guard = kGUARD_EXC_MOD_REFS_NON_FATAL;
		} else {
			guard = kGUARD_EXC_NONE;
		}
	}

	if (guard != kGUARD_EXC_NONE) {
		mach_port_guard_exception(name, payload, guard);
	}
}

/*
 * Collects dyld symbolication information for a given task for telemetry.
 *
 * All output buffers must be pre-initialized (e.g., to empty strings).
 * This function will only populate them if the information is available.
 */
static void
ipc_sec_collect_dyld_symbolication_info(
	task_t task,
	char *shared_cache_base_str,
	char *shared_cache_slide_str,
	char *shared_cache_uuid_str,
	char *main_exec_load_addr_str,
	char *main_exec_slide_str,
	char *main_exec_uuid_str)
{
	/*
	 * Read shared cache info from dyld's all_image_infos structure in userspace.
	 * This is the authoritative source for symbolication, matching what dyld knows.
	 * We read sharedCacheBaseAddress, sharedCacheSlide, and sharedCacheUUID from
	 * the same structure where we'll read the UUID array later.
	 */
	if (task->all_image_info_addr != 0) {
		boolean_t task_64bit_addr = task_has_64Bit_addr(task);
		if (task_64bit_addr) {
			struct user64_dyld_all_image_infos task_image_infos;
			if (copyin(task->all_image_info_addr, &task_image_infos,
			    sizeof(struct user64_dyld_all_image_infos)) == 0) {
				snprintf(shared_cache_base_str, IPC_POLICY_HEX_ADDR_STR_LEN,
				    "0x%llx", task_image_infos.sharedCacheBaseAddress);
				snprintf(shared_cache_slide_str, IPC_POLICY_HEX_ADDR_STR_LEN,
				    "0x%llx", task_image_infos.sharedCacheSlide);
				uuid_unparse_upper(task_image_infos.sharedCacheUUID,
				    shared_cache_uuid_str);

				/* Read main executable info from uuidArray (first entry is main executable) */
				if (task_image_infos.uuidArray != 0 &&
				    task_image_infos.uuidArrayCount > 0) {
					struct user64_dyld_uuid_info main_exec_info;
					if (copyin(task_image_infos.uuidArray, &main_exec_info,
					    sizeof(struct user64_dyld_uuid_info)) == 0) {
						snprintf(main_exec_load_addr_str, IPC_POLICY_HEX_ADDR_STR_LEN,
						    "0x%llx", main_exec_info.imageLoadAddress);
						uuid_unparse_upper(main_exec_info.imageUUID, main_exec_uuid_str);
						/* Main executable slide is implicitly 0 for the load address we get */
						snprintf(main_exec_slide_str, IPC_POLICY_HEX_ADDR_STR_LEN, "0x0");
					}
				}
			}
		}
	}
}

static void
ipc_sec_emit_pending_policy_violation_ca_telemetry(
	ipc_sec_policy_t violation_id,
	char* affected_service_name,
	int aux_data
	)
{
	task_t task = current_task_early();
	if (!task) {
		return;
	}

	char* proc_name = (char *) "unknown";
#ifdef MACH_BSD
	proc_name = proc_name_address(get_bsdtask_info(task));
#endif /* MACH_BSD */
	const char* team_id = csproc_get_identity(current_proc());
	const char* signing_id = csproc_get_teamid(current_proc());

	/* Collect user backtrace */
	uintptr_t user_frames[IPC_POLICY_BACKTRACE_FRAME_COUNT];
	struct backtrace_user_info btinfo = BTUINFO_INIT;
	unsigned int frame_count = backtrace_user(user_frames, IPC_POLICY_BACKTRACE_FRAME_COUNT, NULL, &btinfo);

	/* If backtrace collection failed, send with empty backtrace */
	if (btinfo.btui_error != 0) {
		frame_count = 0;
	}

	/* Collect shared cache information for symbolication */
	char shared_cache_base_str[IPC_POLICY_HEX_ADDR_STR_LEN] = "";
	char shared_cache_slide_str[IPC_POLICY_HEX_ADDR_STR_LEN] = "";
	char shared_cache_uuid_str[IPC_POLICY_UUID_STR_LEN] = "";

	/* Collect main executable information for symbolication */
	char main_exec_load_addr_str[IPC_POLICY_HEX_ADDR_STR_LEN] = "";
	char main_exec_slide_str[IPC_POLICY_HEX_ADDR_STR_LEN] = "";
	char main_exec_uuid_str[IPC_POLICY_UUID_STR_LEN] = "";

	ipc_sec_collect_dyld_symbolication_info(
		task,
		shared_cache_base_str,
		shared_cache_slide_str,
		shared_cache_uuid_str,
		main_exec_load_addr_str,
		main_exec_slide_str,
		main_exec_uuid_str
		);

	ipc_sec_commit_policy_violation_to_ca(
		violation_id,
		proc_name,
		affected_service_name,
		team_id,
		signing_id,
		aux_data,
		user_frames,
		frame_count,
		shared_cache_base_str[0] ? shared_cache_base_str : NULL,
		shared_cache_slide_str[0] ? shared_cache_slide_str : NULL,
		shared_cache_uuid_str[0] ? shared_cache_uuid_str : NULL,
		main_exec_load_addr_str[0] ? main_exec_load_addr_str : NULL,
		main_exec_slide_str[0] ? main_exec_slide_str : NULL,
		main_exec_uuid_str[0] ? main_exec_uuid_str : NULL
		);
}

/*
 *	Routine:	mach_port_guard_ast
 *	Purpose:
 *		Raises an exception for mach port guard violation.
 *	Conditions:
 *		None.
 *	Returns:
 *		None.
 */

void
mach_port_guard_ast(
	thread_t                t,
	mach_exception_data_type_t code,
	mach_exception_data_type_t subcode)
{
	unsigned int reason = EXC_GUARD_DECODE_GUARD_FLAVOR(code);
	task_t task = get_threadtask(t);
	unsigned int behavior = task->task_exc_guard;
	bool fatal = true;

	assert(task == current_task());
	assert(task != kernel_task);

	/* Are we using the unified security policy violation interface? */
	ipc_sec_policy_in_flight_violation_info_t* in_flight_pv_info = &current_thread()->pending_ipc_sec_policy_violation_info;
	ipc_sec_policy_t policy_type = in_flight_pv_info->violated_policy_type;
	if (policy_type != IPC_SEC_POLICY_NONE) {
		/*
		 * We're handling an IPC security policy violation.
		 * Either we're going to emit telemetry, or we'll enforce the violation and kill the process.
		 */
		ipc_sec_policy_config_t* conf = ipc_sec_policy_config_get(policy_type);

		/* And free the backing storage after reading off copies of the fields */
		char affected_service_name[CA_MACH_SERVICE_PORT_NAME_LEN];
		/*
		 * We might not have been able to allocate the buffer for the service name
		 * while triaging the policy violation, so handle that now.
		 */
		if (in_flight_pv_info->affected_service_name == NULL) {
			strlcpy(affected_service_name, "unknown (alloc failed)", sizeof(affected_service_name));
		} else {
			strlcpy(affected_service_name, in_flight_pv_info->affected_service_name, sizeof(affected_service_name));
			kfree_data(in_flight_pv_info->affected_service_name, CA_MACH_SERVICE_PORT_NAME_LEN);
		}
		int ca_aux_data = in_flight_pv_info->ca_aux_data;

		/* And clear the state that stored the in-flight info up to now */
		current_thread()->pending_ipc_sec_policy_violation_info = (ipc_sec_policy_in_flight_violation_info_t){0};

		/*
		 * If we're emitting telemetry for an IPC security policy violation,
		 * we need to query the active telemetry strategy for this violation type.
		 */
		if (conf->enforcement_mode == IPC_SEC_POLICY_MODE_TELEMETRY_ONLY) {
			switch (conf->telemetry_reporting_style) {
			case IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE:
				/* Emit immediately */
				ipc_sec_emit_pending_policy_violation_ca_telemetry(policy_type, affected_service_name, ca_aux_data);
				/* All done here */
				return;
			case IPC_TELEMETRY_MECHANISM_SIMULATED_CRASH_REPORT:
				/*
				 * Simulated crash reports are emitted by the existing logic
				 * later in this function, nothing to do now.
				 */
				break;
			default:
				panic("Programming error: enum case not handled.");
				break;
			}
		}
	}

	if (reason <= MAX_FATAL_kGUARD_EXC_CODE) {
		/*
		 * Fatal Mach port guards - always delivered synchronously if dev mode is on.
		 * Check if anyone has registered for Synchronous EXC_GUARD, if yes then,
		 * deliver it synchronously and then kill the process, else kill the process
		 * and deliver the exception via EXC_CORPSE_NOTIFY.
		 */
		exit_with_fatal_exception_and_notify(get_bsdtask_info(task), OS_REASON_GUARD,
		    EXC_GUARD, code, subcode, PX_FLAGS_NONE);
	} else {
		/*
		 * Mach port guards controlled by task settings.
		 */

		/* Is delivery enabled */
		if ((behavior & TASK_EXC_GUARD_MP_DELIVER) == 0) {
			return;
		}

		/* If only once, make sure we're that once */
		while (behavior & TASK_EXC_GUARD_MP_ONCE) {
			uint32_t new_behavior = behavior & ~TASK_EXC_GUARD_MP_DELIVER;

			if (os_atomic_cmpxchg(&task->task_exc_guard,
			    behavior, new_behavior, relaxed)) {
				break;
			}
			behavior = task->task_exc_guard;
			if ((behavior & TASK_EXC_GUARD_MP_DELIVER) == 0) {
				return;
			}
		}
		fatal = (task->task_exc_guard & TASK_EXC_GUARD_MP_FATAL)
		    && (reason <= MAX_OPTIONAL_kGUARD_EXC_CODE);
		kern_return_t sync_exception_result;
		sync_exception_result = task_exception_notify(EXC_GUARD, code, subcode, fatal);

		if (task->task_exc_guard & TASK_EXC_GUARD_MP_FATAL) {
			if (reason > MAX_OPTIONAL_kGUARD_EXC_CODE) {
				/* generate a simulated crash if not handled synchronously */
				if (sync_exception_result != KERN_SUCCESS) {
					task_violated_guard(code, subcode, NULL, TRUE);
				}
			} else {
				/*
				 * Only generate crash report if synchronous EXC_GUARD wasn't handled,
				 * but it has to die regardless.
				 */
				uint32_t flags = PX_FLAGS_NONE;
				if (sync_exception_result == KERN_SUCCESS) {
					flags |= PX_NO_CRASH_REPORT;
				}

				exception_info_t info = {
					.os_reason = OS_REASON_GUARD,
					.exception_type = EXC_GUARD,
					.mx_code = code,
					.mx_subcode = subcode
				};

				/* kill the task, unconditionally and fatally */
				exit_with_mach_exception(get_bsdtask_info(task), info, flags);
			}
		} else if (task->task_exc_guard & TASK_EXC_GUARD_MP_CORPSE) {
			/* Raise exception via corpse fork if not handled synchronously */
			if (sync_exception_result != KERN_SUCCESS) {
				task_violated_guard(code, subcode, NULL, TRUE);
			}
		}
	}
}

#pragma mark notification policies

bool
ipc_port_can_receive_notifications(
	ipc_space_t             space,
	ipc_port_t              notify_port)
{
	ipc_space_policy_t policy;

	/* NULL notify port has no security restrictions*/
	if (!IP_VALID(notify_port)) {
		return true;
	}

	/* Check if this port type is allowed to receive notifications */
	if (!ipc_policy(notify_port)->pol_can_receive_notifications) {
		mach_port_guard_exception(CAST_MACH_PORT_TO_NAME(notify_port),
		    ip_type(notify_port), kGUARD_EXC_INVALID_NOTIFICATION_PORT);
		/* TODO: disable after verifying telemetry - rdar://164128769 */
		// return false;
	}

	policy = ipc_space_policy(space);
	if (ipc_should_apply_policy(policy, IPC_SPACE_POLICY_CONTAINED)
	    && !ip_is_notification_port(notify_port)) {
		/* contained processes must use notification ports - telemetry for now */
		ipc_triage_policy_violation_and_expect_continue(
			IPC_SEC_POLICY_RESTRICT_REGISTER_NON_NOTIFICATION_PORT,
			space,
			0,
			0,
			notify_port,
			ip_type(notify_port)
			);
	}

	return true;
}

static bool
ipc_allow_service_port_register_pd(
	ipc_port_t              service_port,
	ipc_port_t              notify_port,
	uint64_t                *payload)
{
	if (!ipc_sec_is_policy_enforced(IPC_SEC_POLICY_RESTRICT_MOVE_SERVICE_PORT) ||
	    !IP_VALID(notify_port)) {
		return true;
	}
	/* enforce this policy only on service port types */
	if (ip_is_any_service_port(service_port)) {
		/* Only launchd should be able to register for port destroyed notification on a service port. */
		if (!task_is_initproc(current_task())) {
			*payload = MPG_FLAGS_KERN_FAILURE_TASK;
			return false;
		}
		/* notify_port needs to be immovable */
		if (!ip_is_immovable_receive(notify_port)) {
			*payload = MPG_FLAGS_KERN_FAILURE_NOTIFY_TYPE;
			return false;
		}
		/* notify_port should be owned by launchd */
		if (!task_is_initproc(notify_port->ip_receiver->is_task)) {
			*payload = MPG_FLAGS_KERN_FAILURE_NOTIFY_RECV;
			return false;
		}
	}
	return true;
}

kern_return_t
ipc_allow_register_pd_notification(
	ipc_port_t              pd_port,
	ipc_port_t              notify_port)
{
	uint64_t payload;

	/*
	 * you cannot register for port destroyed notifications
	 * on an immovable receive right (which includes kobjects),
	 * or a (special) reply port or any other port that explicitly disallows them.
	 */
	release_assert(ip_in_a_space(pd_port));
	if (ip_is_immovable_receive(pd_port) ||
	    !ipc_policy(pd_port)->pol_notif_port_destroy) {
		mach_port_guard_exception(ip_type(pd_port), MACH_NOTIFY_PORT_DESTROYED, kGUARD_EXC_INVALID_NOTIFICATION_REQ);
		return KERN_INVALID_RIGHT;
	}

	/* Stronger pd enforcement for service ports */
	if (!ipc_allow_service_port_register_pd(pd_port, notify_port, &payload)) {
		mach_port_guard_exception(0, payload, kGUARD_EXC_KERN_FAILURE);
		return KERN_INVALID_RIGHT;
	}

	/* Allow only one registration of this notification */
	if (ipc_port_has_prdrequest(pd_port)) {
		mach_port_guard_exception(0, MPG_FLAGS_KERN_FAILURE_MULTI_NOTI, kGUARD_EXC_KERN_FAILURE);
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

#pragma mark voucher restrictions

bool
ipc_pol_is_user_voucher_command_permitted(mach_voucher_attr_recipe_command_t command)
{
	switch (command) {
	case MACH_VOUCHER_ATTR_COPY:
	case MACH_VOUCHER_ATTR_REMOVE:
	case MACH_VOUCHER_ATTR_SEND_PREPROCESS:
	case MACH_VOUCHER_ATTR_REDEEM:
	case MACH_VOUCHER_ATTR_USER_DATA_STORE:
	case MACH_VOUCHER_ATTR_BANK_CREATE:
	case MACH_VOUCHER_ATTR_BANK_MODIFY_PERSONA:
#if __BUILDING_XNU_LIB_UNITTEST__
	/*
	 * This vector is in the allow-list just for unit tests, so unit
	 * tests can set up a voucher that should be allowed without performing
	 * any real business logic.
	 */
	case MACH_VOUCHER_ATTR_UNIT_TEST_VECTOR_ALLOWED:
#endif /* __BUILDING_XNU_LIB_UNITTEST__ */
		return true;
	default:
		return false;
	}
}

#pragma mark policy array

__dead2
static void
no_kobject_no_senders(
	ipc_port_t              port,
	mach_port_mscount_t     mscount __unused)
{
	panic("unexpected call to no_senders for object %p, type %d",
	    port, ip_type(port));
}

__dead2
static void
no_label_free(ipc_object_label_t label)
{
	panic("unexpected call to label_free for object type %d, label %p",
	    label.io_type, label.iol_pointer);
}

__security_const_late
struct ipc_object_policy ipc_policy_array[IOT_UNKNOWN] = {
	[IOT_PORT_SET] = {
		.pol_name               = "port set",
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_movable_send       = false,
	},
	[IOT_PORT] = {
		.pol_name               = "port",
		.pol_movability         = IPC_MOVE_POLICY_ALWAYS,
		.pol_movable_send       = true,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
		.pol_notif_port_destroy = true,
		.pol_can_receive_notifications = true,
	},
	[IOT_SERVICE_PORT] = {
		.pol_name               = "service port",
		.pol_movability         = IPC_MOVE_POLICY_ONCE_OR_AFTER_PD,
		.pol_movable_send       = true,
		.pol_label_free         = ipc_service_port_label_dealloc,
		.pol_enforce_reply_semantics = true,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
		.pol_notif_port_destroy = true,
		.pol_can_receive_notifications = true,
	},
	[IOT_BOOTSTRAP_PORT] = {
		.pol_name               = "bootstrap port",
		.pol_movability         = IPC_MOVE_POLICY_NEVER, /* bootstrap port should never leave launchd */
		.pol_movable_send       = true,
		.pol_label_free         = ipc_bootstrap_port_label_dealloc,
		.pol_enforce_reply_semantics = true,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
		.pol_can_receive_notifications = true,
	},
	[IOT_WEAK_SERVICE_PORT] = {
		.pol_name               = "weak service port",
		.pol_movability         = IPC_MOVE_POLICY_ALWAYS,
		.pol_movable_send       = true,
		.pol_label_free         = ipc_service_port_label_dealloc,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
		.pol_notif_port_destroy = true,
		.pol_can_receive_notifications = true,
	},
	[IOT_CONNECTION_PORT] = {
		.pol_name               = "connection port",
		.pol_movability         = IPC_MOVE_POLICY_ONCE,
		.pol_label_free         = ipc_connection_port_label_dealloc,
		.pol_enforce_reply_semantics = true,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
		.pol_notif_port_destroy = true,
		.pol_can_receive_notifications = true,
	},
	[IOT_CONNECTION_PORT_WITH_PORT_ARRAY] = {
		.pol_name               = "conn port with ool port array",
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_movable_send       = true,
		.pol_construct_entitlement = MACH_PORT_CONNECTION_PORT_WITH_PORT_ARRAY,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
	},
	[IOT_NOTIFICATION_PORT] = {
		.pol_name               = "notification port",
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_can_receive_notifications = true,
	},
	[IOT_EXCEPTION_PORT] = {
		.pol_name               = "exception port",
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_movable_send       = true,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
	},
	[IOT_TIMER_PORT] = {
		.pol_name               = "timer port",
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_movable_send       = true,
		.pol_label_free         = mk_timer_port_label_dealloc,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
	},
	[IOT_REPLY_PORT] = {
		.pol_name               = "reply port",
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_notif_dead_name    = true,
	},
	[IOT_SPECIAL_REPLY_PORT] = {
		.pol_name               = "special reply port",
		/*
		 * General use of a special reply port as a receive right
		 * can cause type confusion in the importance code.
		 */
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_notif_dead_name    = true,
	},
	[IOT_WEAK_REPLY_PORT] = {
		.pol_name               = "weak reply port",
		.pol_movability         = IPC_MOVE_POLICY_ALWAYS,
		.pol_movable_send       = true,
		.pol_construct_entitlement = MACH_PORT_WEAK_REPLY_ENTITLEMENT,
		.pol_notif_dead_name    = true,
		.pol_notif_no_senders   = true,
		.pol_notif_port_destroy = true,
	},

	[__IKOT_FIRST ... IOT_UNKNOWN - 1] = {
		.pol_movability         = IPC_MOVE_POLICY_NEVER,
		.pol_enforce_reply_semantics = true,
		.pol_notif_dead_name    = true,
	},
};

__startup_func
static void
ipc_policy_update_from_tunables(void)
{
	if (!ipc_sec_is_policy_enforced(IPC_SEC_POLICY_RESTRICT_MOVE_SERVICE_PORT)) {
		ipc_policy_array[IOT_SERVICE_PORT].pol_movability =
		    IPC_MOVE_POLICY_ALWAYS;
	}
}
STARTUP(TUNABLES, STARTUP_RANK_LAST, ipc_policy_update_from_tunables);

/*
 * Ensure new port types that requires a construction entitlement
 * are marked as immovable.
 */
__startup_func
static void
ipc_policy_construct_entitlement_hardening(void)
{
	/* No need to check kobjects because they are always immovable */
	for (ipc_object_type_t i = 0; i < __IKOT_FIRST; i++) {
		/*
		 * IOT_WEAK_REPLY_PORT is an exception as it used to be
		 * movable. For process opted for enhanced security V2,
		 * kGUARD_EXC_MOVE_WEAK_REPLY_PORT will be thrown when a
		 * weak reply port is being moved.
		 */
		if (i == IOT_WEAK_REPLY_PORT) {
			continue;
		}
		if (ipc_policy_array[i].pol_construct_entitlement) {
			assert(ipc_policy_array[i].pol_movability == IPC_MOVE_POLICY_NEVER);
		}
	}
}
STARTUP(TUNABLES, STARTUP_RANK_LAST, ipc_policy_construct_entitlement_hardening);

__startup_func
void
ipc_kobject_register_startup(ipc_kobject_ops_t ops)
{
	struct ipc_object_policy *pol = &ipc_policy_array[ops->iko_op_type];

	if (pol->pol_name) {
		panic("trying to register kobject(%d) twice", ops->iko_op_type);
	}

	/*
	 * Always make sure kobject ports have immovable receive rights.
	 *
	 * They use the ip_kobject field of the ipc_port structure,
	 * which is unioned with ip_imp_task.
	 *
	 * Thus, general use of a kobject port as a receive right can
	 * cause type confusion in the importance code.
	 */
	ipc_release_assert(pol->pol_movability == IPC_MOVE_POLICY_NEVER);
	if (ops->iko_op_no_senders) {
		pol->pol_notif_no_senders = true;
	}

	pol->pol_name               = ops->iko_op_name;
	pol->pol_kobject_stable     = ops->iko_op_stable;
	pol->pol_kobject_permanent  = ops->iko_op_permanent;
	pol->pol_kobject_no_senders = ops->iko_op_no_senders;
	pol->pol_label_free         = ops->iko_op_label_free;
	pol->pol_movable_send       = ops->iko_op_movable_send;
}

__startup_func
static void
ipc_policy_set_defaults(void)
{
	/*
	 * Check that implicit init to 0 picks the right "values"
	 * for all properties.
	 */
	static_assert(IPC_MOVE_POLICY_NEVER == 0);

	for (uint32_t i = 0; i < IOT_UNKNOWN; i++) {
		struct ipc_object_policy *pol = &ipc_policy_array[i];

		if (!pol->pol_kobject_no_senders) {
			pol->pol_kobject_no_senders = no_kobject_no_senders;
		}
		if (!pol->pol_label_free) {
			pol->pol_label_free = no_label_free;
		}
	}
}
STARTUP(MACH_IPC, STARTUP_RANK_LAST, ipc_policy_set_defaults);

#pragma mark infra for handling security policy violations

#if XNU_TARGET_OS_OSX && CONFIG_CSR
bool
SIP_is_enabled(void)
{
	return csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0;
}
#endif /* XNU_TARGET_OS_OSX && CONFIG_CSR */

static bool
ipc_sec_policy_should_apply_weak_reply_port(void)
{
#if XNU_TARGET_OS_OSX && CONFIG_CSR
	/* Apply policy if SIP is enabled */
	return SIP_is_enabled();
#else
	/* Unconditionally apply policy */
	return true;
#endif /* XNU_TARGET_OS_OSX && CONFIG_CSR */
}

static bool
ipc_sec_policy_should_apply_cv_notification_port(void)
{
	return cv_notif_port_required_enforced;
}

static bool
ipc_sec_policy_should_apply_ool_port_array(void)
{
	return ool_port_array_enforced;
}

__security_const_late
ipc_sec_policy_config_t ipc_sec_policy_array[IPC_SEC_POLICY_COUNT] = {
	[IPC_SEC_POLICY_REQUIRE_REPLY_PORT_SEMANTICS_KOBJECT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_ENFORCEMENT,
		.associated_guard_exc_code = kGUARD_EXC_KOBJECT_REPLY_PORT_SEMANTICS,
	},
	[IPC_SEC_POLICY_REQUIRE_REPLY_PORT_SEMANTICS_BOOTSTRAP_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_ENFORCEMENT,
		.associated_guard_exc_code = kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS,
	},
	[IPC_SEC_POLICY_REQUIRE_REPLY_PORT_SEMANTICS_SERVICE_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_ENFORCEMENT,
		.associated_guard_exc_code = kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS,
	},
	[IPC_SEC_POLICY_DISALLOW_CONSTRUCT_WEAK_REPLY_PORT_WITHOUT_ENTITLEMENT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_ENFORCEMENT,
		.associated_guard_exc_code = kGUARD_EXC_INVALID_MPO_ENTITLEMENT,
		.maybe_should_apply_cb = ipc_sec_policy_should_apply_weak_reply_port,
	},
	[IPC_SEC_POLICY_RESTRICT_MOVE_WEAK_REPLY_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_SIMULATED_CRASH_REPORT,
		.associated_ipc_space_telemetry_flag = IS_FUSE_HAS_MOVE_WEAK_REPLY_PORT_TELEMETRY,
		.associated_guard_exc_code = kGUARD_EXC_MOVE_WEAK_REPLY_PORT,
	},
	[IPC_SEC_POLICY_RESTRICT_MOVE_SERVICE_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_ENFORCEMENT,
		.associated_guard_exc_code = kGUARD_EXC_SERVICE_PORT_VIOLATION_FATAL,
	},
	[IPC_SEC_POLICY_RESTRICT_OOL_PORT_ARRAYS] = {
#if XNU_TARGET_OS_XR
		.enforcement_mode = IPC_SEC_POLICY_MODE_DISABLED,
#else
		.enforcement_mode = IPC_SEC_POLICY_MODE_ENFORCEMENT,
#endif /* XNU_TARGET_OS_XR */
		.maybe_should_apply_cb = ipc_sec_policy_should_apply_ool_port_array,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_SIMULATED_CRASH_REPORT,
		.telemetry_rate_limit_mode = IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_NONE,
		.associated_guard_exc_code = kGUARD_EXC_DESCRIPTOR_VIOLATION,
	},
	[IPC_SEC_POLICY_RESTRICT_INLINE_PORT_DESCRIPTORS] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.telemetry_rate_limit_mode = IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_ONCE_PER_IPC_SPACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_EMITTED_INLINE_PORT_DESC_LIMIT,
	},
	[IPC_SEC_POLICY_RESTRICT_VOUCHER_RECIPE_SIZE] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.telemetry_rate_limit_mode = IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_ONCE_PER_IPC_SPACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_EMITTED_VOUCHER_RECIPE_SIZE_LIMIT,
	},
	[IPC_SEC_POLICY_RESTRICT_VOUCHER_OPERATIONS] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.telemetry_rate_limit_mode = IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_ONCE_PER_IPC_SPACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_EMITTED_RESTRICTED_VOUCHER_OPERATION,
	},
	[IPC_SEC_POLICY_RESTRICT_MOVE_IOT_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_HAS_MOVE_IOT_PORT_TELEMETRY,
	},
	[IPC_SEC_POLICY_RESTRICT_SERVICE_PORT_FOR_EXCEPTION] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_HAS_SERVICE_PORT_EXCEPTION_TELEMETRY,
	},
	[IPC_SEC_POLICY_RESTRICT_CONTAINED_EXCEPTION_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_HAS_CONTAINED_EXCEPTION_TELEMETRY,
	},
	[IPC_SEC_POLICY_RESTRICT_REGISTER_NON_NOTIFICATION_PORT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_SIMULATED_CRASH_REPORT,
		.telemetry_rate_limit_mode = IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_NONE,
		.associated_guard_exc_code = kGUARD_EXC_CV_NOTIFICATION_PORT_REQ,
		.maybe_should_apply_cb = ipc_sec_policy_should_apply_cv_notification_port,
	},
	[IPC_SEC_POLICY_RESTRICT_MACH_EXC_THREAD_SET_STATE] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		// .associated_guard_exc_code = kGUARD_EXC_MACH_EXC_THREAD_SET_STATE,
		// .telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_SIMULATED_CRASH_REPORT,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_HAS_MACH_EXC_TSS_TELEMETRY,
	},
	[IPC_SEC_POLICY_RESTRICT_EXCEPTION_PORT_NOT_IN_SPACE] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_DISABLED,
	},
	[IPC_SEC_POLICY_DISALLOW_BOOTSTRAP_PORT_FOR_NOTIFICATION] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_DISABLED,
	},
	[IPC_SEC_POLICY_RESTRICT_MESSAGE_QUEUE_SIZE] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_DISABLED,
	},
	[IPC_SEC_POLICY_RESTRICT_PER_PROCESS_MESSAGE_LIMIT] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_DISABLED,
	},
	[IPC_SEC_POLICY_RESTRICT_IMMOVABLE_SEND_RIGHT_CREATION] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_TELEMETRY_ONLY,
		.telemetry_reporting_style = IPC_TELEMETRY_MECHANISM_CA_WITH_USER_BACKTRACE,
		.telemetry_rate_limit_mode = IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_ONCE_PER_IPC_SPACE,
		.associated_ipc_space_telemetry_flag = IS_FUSE_HAS_IMMOVABLE_SEND_RIGHT_TELEMETRY,
	},
	[IPC_SEC_POLICY_DISALLOW_REPLY_PORT_WITH_MUTIPLE_SO] = {
		.enforcement_mode = IPC_SEC_POLICY_MODE_DISABLED,
	},
};

#if DEVELOPMENT || DEBUG
/*!
 * @brief
 * Auto-detect security policy misconfigurations that specify invalid state.
 *
 * @discussion
 * This validator panics the system at startup if a misconfiguration is detected.
 */
__startup_func
static void
ipc_sec_policy_configs_validate(void)
{
	for (uint32_t i = IPC_SEC_POLICY_NONE + 1; i < IPC_SEC_POLICY_UNKNOWN; i++) {
		ipc_sec_policy_config_t* conf = ipc_sec_policy_config_get(i);
		if (conf->enforcement_mode == IPC_SEC_POLICY_MODE_ENFORCEMENT) {
			/* Enforced policies must configure an associated kGUARD_EXC code */
			if (conf->associated_guard_exc_code == kGUARD_EXC_NONE) {
				panic("Expected policy %d to have a mapped kGUARD_EXC code.", i);
			}
			/* And the kGUARD_EXC code must be in the fatal range */
			if (conf->associated_guard_exc_code > MAX_FATAL_kGUARD_EXC_CODE) {
				panic("Expected policy %d to have a fatal kGUARD_EXC code, but found non-fatal code %d.",
				    i,
				    conf->associated_guard_exc_code);
			}
		} else if (conf->enforcement_mode == IPC_SEC_POLICY_MODE_TELEMETRY_ONLY) {
			/* Telemetry-only policies must configure a telemetry mechanism */
			if (conf->telemetry_reporting_style == IPC_TELEMETRY_MECHANISM_NONE) {
				panic("Expected telemetry-only policy %d to have a telemetry reporting style configured.", i);
			}
			/*
			 * And they must specify an IPC space flag to prevent overzealous emission.
			 * Unless the policy has been explicitly configured to disable rate-limiting per IPC space.
			 */
			if (conf->telemetry_rate_limit_mode != IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_NONE &&
			    (conf->associated_ipc_space_telemetry_flag == IS_FUSE_NONE ||
			    conf->associated_ipc_space_telemetry_flag > IS_FUSE_MAX)) {
				panic("Expected a valid IPC space telemetry flag for rate-limited policy %d, found %d",
				    i,
				    conf->associated_ipc_space_telemetry_flag);
			}
			/*
			 * If configured to emit via simulated crash reports, we need an appropriate
			 * associated kGUARD_EXC code.
			 */
			if (conf->telemetry_reporting_style == IPC_TELEMETRY_MECHANISM_SIMULATED_CRASH_REPORT) {
				if (conf->associated_guard_exc_code == kGUARD_EXC_NONE) {
					panic("Expected policy %d to have a mapped kGUARD_EXC code.", i);
				}
				/* And the kGUARD_EXC code must be in the non-fatal range */
				if (conf->associated_guard_exc_code <= MAX_FATAL_kGUARD_EXC_CODE) {
					panic("Expected policy %d to have a non-fatal kGUARD_EXC code, but found fatal code %d.",
					    i,
					    conf->associated_guard_exc_code);
				}
			}
		} else if (conf->enforcement_mode == IPC_SEC_POLICY_MODE_NONE) {
			/* Ensure the `enforcement_mode` field is always explicitly initialized */
			panic("You must assign each IPC policy's `enforcement_mode`, IPC_SEC_POLICY_MODE_NONE is not valid.");
		} else if (conf->enforcement_mode == IPC_SEC_POLICY_MODE_DISABLED) {
			/* No validations on disabled policies */
		} else {
			panic("If you've added a new enforcement mode, update this site to add appropriate validations.");
		}
	}
}
STARTUP(TUNABLES, STARTUP_RANK_LAST, ipc_sec_policy_configs_validate);
#endif /* DEVELOPMENT || DEBUG */

ipc_sec_policy_config_t*
ipc_sec_policy_config_get(ipc_sec_policy_t p)
{
	/* If this fails it indicates a programming error. */
	assert3u(p, <, IPC_SEC_POLICY_UNKNOWN);
	return &ipc_sec_policy_array[p];
}

bool
ipc_sec_is_policy_enforced(ipc_sec_policy_t p)
{
	ipc_sec_policy_config_t* conf = ipc_sec_policy_config_get(p);
	bool is_policy_enforced = conf->enforcement_mode == IPC_SEC_POLICY_MODE_ENFORCEMENT;
	bool has_policy_chosen_to_elide_violation = (conf->maybe_should_apply_cb &&
	    !conf->maybe_should_apply_cb());
	return is_policy_enforced && !has_policy_chosen_to_elide_violation;
}

/*!
 * @brief
 * Query what the system and IPC space think about emitting a particular telemetry type.
 *
 * @discussion
 * Note that this contains a test-or-set, so it's a modifying operation.
 */
static bool
_ipc_test_or_set_should_emit_telemetry_for_telemetry_mode_policy_violation(
	ipc_sec_policy_config_t* policy_config,
	ipc_space_t maybe_space
	)
{
	/*
	 * Further qualify whether to emit telemetry.
	 *
	 * Don't emit if telemetry is globally disabled.
	 */
	bool should_emit = ipcpv_telemetry_enabled;

	/* Don't emit if this policy rate-limits by IPC space and we've already emitted for this space */
	if (
		should_emit &&
		policy_config->telemetry_rate_limit_mode == IPC_SEC_POLICY_TELEMETRY_RATE_LIMIT_ONCE_PER_IPC_SPACE
		) {
		/* The IPC space must have been specified */
		assert3p(maybe_space, !=, IPC_SPACE_NULL);
		if (ipc_space_test_or_set_telemetry_type(maybe_space, policy_config->associated_ipc_space_telemetry_flag)) {
			should_emit = false;
		}
	}

	return should_emit;
}

/*!
 * @brief
 * Returns whether we've decided to emit telemetry (and whether we should therefore set up the AST).
 */
static bool
_ipc_triage_telemetry_mode_policy_violation(
	ipc_sec_policy_config_t* policy_config,
	ipc_space_t maybe_space,
	ipc_sec_policy_in_flight_violation_info_t* in_flight_info,
	ipc_port_t maybe_ca_violating_port,
	int maybe_ca_aux_data
	)
{
	if (!_ipc_test_or_set_should_emit_telemetry_for_telemetry_mode_policy_violation(policy_config, maybe_space)) {
		/* Do not emit telemetry despite a violation being detected while in telemetry mode */
		return false;
	}

	/*
	 * Stash the service port name.
	 * We must copy it off now, as it's not safe to retain the port till the AST.
	 */
	char* service_name = (char *) "unknown";
	/*
	 * We need to allocate some heap storage to store the service name.
	 * We're on a hot path, though, so we're only able to do this if Z_NOWAIT
	 * succeeds. In the case for which we're unable to allocate here, just
	 * don't set a service name pointer, which we'll later detect.
	 */
	in_flight_info->affected_service_name = (char*)kalloc_data(CA_MACH_SERVICE_PORT_NAME_LEN, Z_NOWAIT | Z_ZERO);
	if (in_flight_info->affected_service_name != NULL) {
#if CONFIG_SERVICE_PORT_INFO
		if (IP_VALID(maybe_ca_violating_port)) {
			/*
			 * dest_port lock must be held to avoid race condition
			 * when accessing ip_splabel rdar://139066947
			 */
			ipc_object_label_t label = ip_mq_lock_label_get(maybe_ca_violating_port);
			if (io_state_active(label.io_state)) {
				if (ip_is_any_service_port_type(label.io_type)) {
					struct mach_service_port_info sp_info;
					ipc_service_port_label_get_info(label.iol_service, &sp_info);
					service_name = sp_info.mspi_string_name;
				} else if (ip_is_bootstrap_port_type(label.io_type)) {
					struct mach_service_port_info sp_info;
					ipc_bootstrap_port_label_get_info(label.iol_bootstrap, &sp_info);
					service_name = sp_info.mspi_string_name;
				}
			}
			ip_mq_unlock_label_put(maybe_ca_violating_port, &label);
		}
#endif /* CONFIG_SERVICE_PORT_INFO */
		strlcpy(in_flight_info->affected_service_name,
		    service_name,
		    CA_MACH_SERVICE_PORT_NAME_LEN);
	}
	/* And stash the caller-provided aux data that we'll stuff into the telemetry event */
	in_flight_info->ca_aux_data = maybe_ca_aux_data;

	return true;
}

ipc_sec_policy_violation_action_t
ipc_triage_policy_violation(
	ipc_sec_policy_t policy,
	ipc_space_t maybe_space,
	/* Arguments to pipe through to an EXC_GUARD payload */
	uint32_t maybe_exc_target,
	uint64_t maybe_exc_payload,
	/* Arguments to pipe through to a CA payload */
	ipc_port_t maybe_ca_violating_port,
	int maybe_ca_aux_data
	)
{
	ipc_sec_policy_violation_action_t action;
	bool should_setup_ast_handler = false;
	ipc_sec_policy_config_t* policy_config = ipc_sec_policy_config_get(policy);

	/*
	 * First up, check in with this policy whether it's currently relevant:
	 *  - Do nothing for disabled policies
	 *  - Allow the policy to make a runtime decision on whether it should be applied
	 */
	bool is_static_config_disabled = policy_config->enforcement_mode == IPC_SEC_POLICY_MODE_DISABLED;
	bool has_policy_chosen_to_elide_violation = (policy_config->maybe_should_apply_cb &&
	    !policy_config->maybe_should_apply_cb());
	if (is_static_config_disabled || has_policy_chosen_to_elide_violation) {
		/* Nothing to do, allow the action to continue. */
		return IPC_SEC_POLICY_VIOLATION_ACTION_CONTINUE;
	}

	/* Keep track of metadata that will be passed up to the AST, if we decide to raise one */
	ipc_sec_policy_in_flight_violation_info_t* in_flight_info = &current_thread()->pending_ipc_sec_policy_violation_info;

	if (policy_config->enforcement_mode == IPC_SEC_POLICY_MODE_TELEMETRY_ONLY) {
		/* Telemetry-only mode */
		action = IPC_SEC_POLICY_VIOLATION_ACTION_CONTINUE;
		should_setup_ast_handler = _ipc_triage_telemetry_mode_policy_violation(
			policy_config,
			maybe_space,
			in_flight_info,
			maybe_ca_violating_port,
			maybe_ca_aux_data
			);
	} else if (policy_config->enforcement_mode == IPC_SEC_POLICY_MODE_ENFORCEMENT) {
		/* Enforcement mode */
		action = IPC_SEC_POLICY_VIOLATION_ACTION_DENY;
		should_setup_ast_handler = true;
	} else {
		panic("Programming error? Unrecognized enforcement mode %d", policy_config->enforcement_mode);
	}

	if (should_setup_ast_handler) {
		mach_port_guard_exception(maybe_exc_target, maybe_exc_payload, policy_config->associated_guard_exc_code);
		/* Note we only expect/allow a single pending violation per syscall */
		in_flight_info->violated_policy_type = policy;
	} else {
		/*
		 * Throw away the pending state we built up.
		 * (Note particularly that there is one path on the telemetry path that allocates,
		 *  but this path only runs when should_setup_ast_handler == true, so we have no
		 *  need to worry about freeing this allocation here.)
		 */
	}

	return action;
}

void
ipc_triage_policy_violation_and_expect_continue(
	ipc_sec_policy_t policy,
	ipc_space_t maybe_space,
	uint32_t target,
	uint64_t payload,
	ipc_port_t maybe_violating_port,
	int maybe_aux_data
	)
{
	ipc_sec_policy_violation_action_t action = ipc_triage_policy_violation(
		policy,
		maybe_space,
		target,
		payload,
		maybe_violating_port,
		maybe_aux_data
		);
	if (action != IPC_SEC_POLICY_VIOLATION_ACTION_CONTINUE) {
		panic("Expected to continue after handling IPC security policy violation policy %d, but got %d",
		    policy,
		    action);
	}
}

void
ipc_triage_policy_violation_and_expect_deny(
	ipc_sec_policy_t policy,
	ipc_space_t maybe_space,
	uint32_t target,
	uint64_t payload,
	ipc_port_t maybe_violating_port,
	int maybe_aux_data
	)
{
	ipc_sec_policy_violation_action_t action = ipc_triage_policy_violation(
		policy,
		maybe_space,
		target,
		payload,
		maybe_violating_port,
		maybe_aux_data
		);
	if (action != IPC_SEC_POLICY_VIOLATION_ACTION_DENY) {
		panic("Expected to deny after handling IPC security policy violation policy %d, but got %d", policy, action);
	}
}
