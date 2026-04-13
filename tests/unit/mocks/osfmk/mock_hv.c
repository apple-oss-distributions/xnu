/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include "mock_hv.h"
#include "mocks/osfmk/unit_test_utils.h"

T_MOCK_F(hv_return_t,
hv_call,
(uint64_t fn, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t * ret_val),
(fn, arg0, arg1, arg2, arg3, arg4, ret_val)) {
	(void)fn;
	(void)arg0;
	(void)arg1;
	(void)arg2;
	(void)arg3;
	(void)arg4;
	(void)ret_val;
	return HV_SUCCESS;
}

T_MOCK_F(hv_return_t,
hv_trap_vcpu_set_address_space,
(hv_vm_space_t space),
(space)) {
	(void)space;
	return HV_SUCCESS;
}

T_MOCK_F(void,
hv_enter_guest,
(arm_guest_context_t * guest_context, arm_host_context_t * host_context),
(guest_context, host_context)) {
	(void)guest_context;
	(void)host_context;
}

T_MOCK_F(void,
_hv_vcpu_save_state_with_mask,
(hv_vcpu_t * vcpu, uint64_t state_mask),
(vcpu, state_mask)) {
	(void)vcpu;
	(void)state_mask;
}

T_MOCK_F(void,
_hv_load_control_regs,
(hv_vcpu_t * vcpu),
(vcpu)) {
	(void)vcpu;
}

T_MOCK_F(void,
_hv_load_guest_vgic_regs,
(hv_vcpu_t * vcpu),
(vcpu)) {
	(void)vcpu;
}

T_MOCK_F(void,
_hv_load_guest_sysregs,
(hv_vcpu_t * vcpu),
(vcpu)) {
	(void)vcpu;
}

T_MOCK_F(void,
_hv_load_guest_dbgregs,
(hv_vcpu_t * vcpu),
(vcpu)) {
	(void)vcpu;
}

T_MOCK_F(void,
_hv_load_guest_extregs,
(hv_vcpu_t * vcpu),
(vcpu)) {
	(void)vcpu;
}

T_MOCK(hv_return_t,
hv_space_create,
(hv_vm_t * vm, uint64_t min_ipa, uint64_t ipa_size, uint32_t granule, uint64_t *out_asid),
(vm, min_ipa, ipa_size, granule, out_asid));


T_MOCK(const hv_paranested_measurement_t *,
hv_get_native_measurement,
(void),
())

T_MOCK(const hv_paranested_measurement_t *,
hv_get_shared_measurement,
(void),
())

T_MOCK(const hv_paranested_measurement_t *,
hv_get_supported_measurement_nofail,
(hv_context_version_major_t major_version),
(major_version))

T_MOCK(bool,
hv_major_version_compatible,
(hv_context_version_major_t major_version),
(major_version))

T_MOCK(void,
hv_convert_context_major_version,
(const void *src, hv_context_version_major_t src_version_major,
void *dst, hv_context_version_major_t dst_version_major, bool copy_ro),
(src, src_version_major, dst, dst_version_major, copy_ro))

T_MOCK(bool,
hv_guest_has_major_version_mismatch,
(void),
())

T_MOCK(bool,
hv_guest_has_context_measurement_mismatch,
(void),
())

T_MOCK_F(
	uint64_t,
	testable_arm_rsr64,
	(const char *regname),
	(regname)) {
	(void)regname;
	return 0;
}

T_MOCK_F(
	void,
	testable_arm_wsr64,
	(const char *regname, uint64_t value),
	(regname, value)) {
	(void)regname;
	(void)value;
}

T_MOCK(bool,
hv_init,
(void),
())

T_MOCK(hv_return_t,
hv_get_host_capabilities,
(vm_offset_t caps_buffer),
(caps_buffer))
