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

#include "mock_hv_vcpu.h"
#include "mocks/dt_proxy.h"
#include <arm64/hv/hv_interface.h>

// Constants for mock vCPU creation
const uint64_t mock_nested_asid = HV_VM_SPACE_DEFAULT + 1;
const hv_paranested_measurement_t shared_measurement = HV_PARANESTED_MEASUREMENT_T_CONSTRUCTOR;
const uint64_t nested_vm_id = 0;

// Shared mock structures for nested guest mapping
struct pmap _nested_guest_pmap = {
	.vmid = 3,
};

struct _vm_map _nested_guest_map = {
	.pmap = &_nested_guest_pmap,
};

vm_map_t mock_nested_guest_map = &_nested_guest_map;

hv_vcpu_t *
create_mock_vcpu_ext(const mock_vcpu_config_t *config)
{
	// Clear ASTs that have been marked as pending by the unit test initialization.
	current_cpu_datap()->cpu_pending_ast = 0;

	hv_vcpu_t *vcpu = calloc(1, sizeof(hv_vcpu_t));
	PT_QUIET; PT_ASSERT_NOTNULL(vcpu, "Failed to allocate mock vCPU");

	// Allocate and initialize guest context
	arm_guest_context_t *guest_context = calloc(1, sizeof(arm_guest_context_t));
	PT_QUIET; PT_ASSERT_NOTNULL(guest_context, "Failed to allocate guest context");

	vcpu->kif = guest_context;
	vcpu->host_context.guest_context = guest_context;

	// Initialize VM capabilities
	hv_vm_t *vm = calloc(1, sizeof(hv_vm_t));
	PT_QUIET; PT_ASSERT_NOTNULL(vm, "Failed to allocate mock VM");
	vcpu->vm = vm;

	// Initialize nested vCPU array to zero (NESTED_VCPU_INVALID state)
	for (unsigned i = 0; i < HV_NESTED_VM_MAX; i++) {
		vm->nested_vms[i] = calloc(1, sizeof(hv_nested_vm_t));
	}

	hv_nested_vm_t *nvm = vm->nested_vms[nested_vm_id];

	hv_vm_percpu_t *percpu = calloc(1, sizeof(hv_vm_percpu_t));
	vm->percpu = percpu;
	vm->paranested_enabled = config->paranested_enabled;
	vm->paranested_initialized = config->paranested_initialized;
	vm->guest_arm_hv_state_version = ARM_HV_STATE_VER;
	vm->shared_measurement = &shared_measurement;
	vm->mtx = lck_mtx_alloc_init(&hv_lck_grp, LCK_ATTR_NULL);
	PT_QUIET; PT_ASSERT_NOTNULL(vm->mtx, "Failed to allocate VM mutex");

	vm->isa = config->isa;

	// Initialize default VM space and create a mock guest_map
	hv_return_t ret = hv_space_create_default(vm, &((hv_vm_create_t) {
		.min_ipa = 0x100000000,
		.ipa_size = 0x100000000,
		.granule = 16 * 1024,
		.flags = 0,
		.isa = config->isa,
	}));
	PT_ASSERT_TRUE(ret == HV_SUCCESS, "Create default space");
	vcpu->host_context.guest_map = vm->default_space;

	vcpu->generation = 1;
	nvm->space = mock_nested_asid;

	hv_set_vcpu(vcpu);

	return vcpu;
}

hv_vcpu_t *
create_mock_vcpu(void)
{
	mock_vcpu_config_t config = {
		.paranested_initialized = true,
		.paranested_enabled = true,
		.isa = _HV_VM_ISA_APPLE,
	};
	return create_mock_vcpu_ext(&config);
}

void
free_mock_vcpu(hv_vcpu_t *vcpu)
{
	free(vcpu->kif);

	// Clean up any nested vCPU contexts that were allocated
	for (int i = 0; i < HV_NESTED_VM_MAX; i++) {
		for (int j = 0; j < HV_VCPU_MAX; j++) {
			hv_nested_vcpu_t *nested_vcpu = &vcpu->vm->nested_vms[i]->vcpu_byid[j];
			if (nested_vcpu->kif) {
				free(nested_vcpu->kif);
			}
		}
		T_MOCK_ORIGINAL(mach_port_deallocate)(current_space(), (mach_port_name_t)vcpu->vm->nested_vms[i]->space);
		free(vcpu->vm->nested_vms[i]);
	}

	free(vcpu->vm->percpu);
	free(vcpu->vm);
	free(vcpu);
}

// vCPU state assertion functions
void
assert_vcpu_in_root_guest(hv_vcpu_t *vcpu)
{
	PT_QUIET; PT_ASSERT_TRUE(vcpu->nested_vcpu == NULL, "Should run root vCPU");
	PT_QUIET; PT_ASSERT_TRUE((uintptr_t)vcpu->host_context.guest_context == (uintptr_t)vcpu->kif, "Should run root guest context");
	PT_QUIET; PT_ASSERT_TRUE((uintptr_t)vcpu->host_context.guest_map == (uintptr_t)vcpu->vm->default_space, "Should run default space");
}

void
assert_vcpu_in_nested_guest(hv_vcpu_t *vcpu, hv_nested_vcpu_t *nested_vcpu)
{
	PT_QUIET; PT_ASSERT_TRUE((uintptr_t)vcpu->nested_vcpu == (uintptr_t)nested_vcpu, "Should run nested vCPU");
	PT_QUIET; PT_ASSERT_TRUE((uintptr_t)vcpu->host_context.guest_context == (uintptr_t)nested_vcpu->kif, "Should run nested guest context");
	PT_QUIET; PT_ASSERT_TRUE((uintptr_t)vcpu->host_context.guest_map != (uintptr_t)vcpu->vm->default_space, "Should run nested space");
	PT_QUIET; PT_ASSERT_TRUE(nested_vcpu->state == NESTED_VCPU_BUSY, "Nested vCPU should be busy");
}

// HVC mocking functions
void
mock_nested_hvc(arm_guest_context_t *context, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4)
{
	// Set up the guest context to simulate an HVC call for nested vCPU run
	// ESR for HVC_64 with immediate value 0
	context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
	uint32_t hvc_esr = (0x16 << 26) | (0 << 5); // ESR_EC_HVC_64 with imm16=0
	context->ro.exit.vmexit_esr = hvc_esr;

	// Set up HVC call parameters in guest registers
	context->rw.regs.x[0] = x0;
	context->rw.regs.x[1] = x1;
	context->rw.regs.x[2] = x2;
	context->rw.regs.x[3] = x3;
	context->rw.regs.x[4] = x4;
}

void
mock_nested_vm_init(arm_guest_context_t *context, uint64_t min_ipa, uint64_t ipa_size, uint64_t granule, hv_vm_isa_t isa)
{
	mock_nested_hvc(context, VMAPPLE_NESTED_VM_INIT, min_ipa, ipa_size, granule, isa);
}

void
mock_nested_vm_destroy(arm_guest_context_t *context, uint64_t vm_id)
{
	mock_nested_hvc(context, VMAPPLE_NESTED_VM_DESTROY, vm_id, 0, 0, 0);
}

void
mock_nested_init(arm_guest_context_t *context, uint64_t measurement_pair_ipa, uint64_t measurement_pair_size)
{
	mock_nested_hvc(context, VMAPPLE_NESTED_INIT, measurement_pair_ipa, measurement_pair_size, 0, 0);
}

void
mock_context_version(arm_guest_context_t *context, uint16_t guest_min_version, uint16_t guest_max_version)
{
	mock_nested_hvc(context, VMAPPLE_NESTED_CONTEXT_VERSION, guest_min_version, guest_max_version, 0, 0);
}

void
mock_nested_vcpu_init(arm_guest_context_t *context, uint64_t nested_context_ipa)
{
	mock_nested_hvc(context, VMAPPLE_NESTED_VCPU_INIT, 0, 0, nested_context_ipa, 0);
}

void
mock_nested_vcpu_run(arm_guest_context_t *context, uint64_t nested_vcpu_id)
{
	mock_nested_hvc(context, VMAPPLE_NESTED_VCPU_RUN, nested_vm_id, nested_vcpu_id, 0, 0);
}

void
mock_nested_vcpu_run_cancel(arm_guest_context_t *context)
{
	static const uint64_t nested_vcpu_id = 0;
	static const uint64_t nested_vcpu_mask = 1ull << nested_vcpu_id;
	mock_nested_hvc(context, VMAPPLE_NESTED_VCPU_RUN_CANCEL, nested_vm_id, nested_vcpu_mask, 0, 0);
}

void
mock_nested_vcpu_destroy(arm_guest_context_t *context)
{
	static const uint64_t nested_vcpu_id = 0;
	mock_nested_hvc(context, VMAPPLE_NESTED_VCPU_DESTROY, nested_vm_id, nested_vcpu_id, 0, 0);
}

void
mock_hv_capabilities(arm_guest_context_t *context, uint64_t caps_buffer_ipa)
{
	// Set up guest context to simulate HV capabilities trap
	// Use mock_nested_hvc but with the trap constant
	context->rw.regs.x[0] = TRAP_HV_CAPABILITIES;  // Trap number
	context->rw.regs.x[1] = caps_buffer_ipa;       // Buffer IPA for capabilities
	context->rw.regs.x[2] = 0;
	context->rw.regs.x[3] = 0;
	context->rw.regs.x[4] = 0;
	context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
}
