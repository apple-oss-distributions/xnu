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

#include <darwintest.h>
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_cpu.h"
#include "mocks/osfmk/mock_hv.h"
#include "mocks/osfmk/mock_vm.h"
#include "mocks/osfmk/mock_vm_map.h"
#include "mocks/osfmk/mock_mach_port.h"
#include "mocks/osfmk/mock_hv_vcpu.h"

#include <arm64/hv/hv_kern_types.h>
#include <arm64/hv/hv_vm.h>
#include <arm64/hv/hv_space.h>
#include <arm64/hv/hv_vcpu.h>
#include <arm64/hv_hvc.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>
#include <mach/mach.h>
#include <vm/vm_kern_xnu.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.nested_vcpu_tests"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("vincenzo_scotti")
	);

bool hv_is_nested_vm_valid(hv_nested_vm_t *nvm);

// Helper functions for test setup

static const uint64_t nested_ro_context_ipa = 0x5000000;
static const vm_prot_t nested_ro_context_prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
static const bool paranested_initialized = true;


static hv_nested_vcpu_t *
setup_nested_vcpu(hv_vcpu_t *vcpu, uint64_t nested_vcpu_id)
{
	// Set up a nested vCPU at [0][0] that's ready to run
	hv_nested_vcpu_t *nested_vcpu = &vcpu->vm->nested_vms[nested_vm_id]->vcpu_byid[nested_vcpu_id];
	nested_vcpu->kif = calloc(1, sizeof(arm_guest_context_t));
	T_QUIET; T_ASSERT_NOTNULL(nested_vcpu->kif, "Failed to allocate nested context");
	nested_vcpu->state = NESTED_VCPU_IDLE;
	nested_vcpu->nested_ro_context_ipa = nested_ro_context_ipa;
	nested_vcpu->nested_ro_context_prot = nested_ro_context_prot;
	nested_vcpu->generation = 1 + nested_vcpu_id;
	return nested_vcpu;
}

// Mock hv_trap_vcpu_set_address_space to update the guest_map
T_MOCK_SET_PERM_FUNC(hv_return_t, hv_trap_vcpu_set_address_space, (uint64_t asid))
{
	hv_vcpu_t *vcpu = hv_get_vcpu();
	assert(vcpu != NULL);
	if (asid == HV_VM_SPACE_DEFAULT) {
		vcpu->host_context.guest_map = (vm_map_t)(uintptr_t)vcpu->vm->default_space;
	} else {
		T_EXPECT_EQ(asid, mock_nested_asid, "Check nested ASID");
		vcpu->host_context.guest_map = mock_nested_guest_map;
	}
	return HV_SUCCESS;
}

// Test Cases

T_DECL(vcpu_run_nested_guest_hvc_flow, "Root guest HVC request -> nested guest -> exit NONE -> root guest")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count = 0;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			// Mock a nested guest taking a synchronous exception to be routed to the root guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
			break;

		case 3:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Check nested run return value");
			T_EXPECT_EQ(nested_vcpu->kif->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_SYNC, "Check nested vmexit reason");
			T_EXPECT_EQ((uint64_t)nested_vcpu->kif->ro.exit.vmexit_reason,
			vcpu->host_context.guest_context->rw.regs.x[1], "Check nested vmexit consistency");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 3, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(vcpu_run_error_entering_nested_space, "Test error while entering the nested guest space")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count = 0;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	// Mock hv_trap_vcpu_set_address_space to update the guest_map. Mock a failure when trying to
	// activate the nested guest map.
	T_MOCK_SET_CALLBACK(hv_trap_vcpu_set_address_space, hv_return_t, (uint64_t asid), {
		if (asid == HV_VM_SPACE_DEFAULT) {
		        vcpu->host_context.guest_map = (vm_map_t)(uintptr_t)vcpu->vm->default_space;
		        return HV_SUCCESS;
		}
		T_EXPECT_EQ(asid, mock_nested_asid, "Check nested ASID");
		return HV_ERROR;
	});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_ERROR, "Root guest should receive error");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(vcpu_run_error_exiting_nested_space, "Test error while leaving the nested guest space")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count = 0;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	// Mock hv_trap_vcpu_set_address_space to update the guest_map. Mock a failure when trying to
	// return to the root guest map.
	T_MOCK_SET_CALLBACK(hv_trap_vcpu_set_address_space, hv_return_t, (uint64_t asid), {
		if (asid == HV_VM_SPACE_DEFAULT) {
		        return HV_ERROR;
		}
		T_EXPECT_EQ(asid, mock_nested_asid, "Check nested ASID");
		vcpu->host_context.guest_map = mock_nested_guest_map;
		return HV_SUCCESS;
	});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_ERROR, "Should propagate failure to host userspace");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_init_error_remapping_context, "Test error while remapping nested context")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count = 0;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	T_MOCK_SET_RETVAL(mach_vm_remap_new_kernel, kern_return_t, KERN_NO_SPACE);

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_init(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_NO_RESOURCES, "Root guest should receive error");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_init_error_wiring_context, "Test error while wiring nested context")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static bool remap_called;
	static bool deallocate_called;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static uint64_t nested_context_ipa = 0x4000;
	static uint64_t nested_context_remapped = 0x100000000;

	T_MOCK_SET_CALLBACK(mach_vm_remap_new_kernel, kern_return_t, (
		    vm_map_t                target_map,
		    mach_vm_offset_ut      * address,
		    mach_vm_size_ut         size,
		    mach_vm_offset_ut       mask,
		    vm_map_kernel_flags_t   vmk_flags,
		    vm_map_t                src_map,
		    mach_vm_offset_ut       memory_address,
		    boolean_t               copy,
		    vm_prot_ut             * cur_protection,
		    vm_prot_ut             * max_protection,
		    vm_inherit_ut           inheritance
		    ), {
		T_QUIET; T_ASSERT_FALSE(remap_called, "Check that we're not remapping twice");
		T_QUIET; T_ASSERT_EQ_PTR(target_map, kernel_map, "Check remap target space");
		T_QUIET; T_ASSERT_EQ_PTR(src_map, vcpu->vm->default_space, "Check remap source space");
		T_QUIET; T_ASSERT_EQ(memory_address, nested_context_ipa, "Check remap source address");
		remap_called = true;
		*address = nested_context_remapped;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(mach_vm_deallocate_kernel, kern_return_t,
	    (
		    vm_map_t target,
		    mach_vm_address_t address,
		    mach_vm_size_t size
	    ), {
		T_QUIET; T_ASSERT_FALSE(deallocate_called, "Check that we're not deallocating twice");
		T_QUIET; T_ASSERT_EQ_PTR(target, kernel_map, "Check remap target space");
		T_QUIET; T_ASSERT_EQ(address, nested_context_remapped, "Check remapped context address");
		T_QUIET; T_ASSERT_EQ((size_t)size, sizeof(arm_guest_context_t), "Check remapped context size");
		deallocate_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_RETVAL(vm_map_wire_kernel, kern_return_t, KERN_NO_SPACE);

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_init(vcpu->host_context.guest_context, nested_context_ipa);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_NO_RESOURCES, "Root guest should receive error");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, 0);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_TRUE(remap_called, "Check that we've remapped the nested context");
	T_EXPECT_TRUE(deallocate_called, "Check that we've unmapped the nested context");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_init_error_ipa_lookup, "Test error while looking up IPA in guest map")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static bool remap_called;
	static bool deallocate_called;
	static bool wire_called;
	static bool unwire_called;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static uint64_t nested_context_ipa = 0x4000;
	static uint64_t nested_context_remapped = 0x100000000;

	T_MOCK_SET_CALLBACK(mach_vm_remap_new_kernel, kern_return_t, (
		    vm_map_t                target_map,
		    mach_vm_offset_ut      * address,
		    mach_vm_size_ut         size,
		    mach_vm_offset_ut       mask,
		    vm_map_kernel_flags_t   vmk_flags,
		    vm_map_t                src_map,
		    mach_vm_offset_ut       memory_address,
		    boolean_t               copy,
		    vm_prot_ut             * cur_protection,
		    vm_prot_ut             * max_protection,
		    vm_inherit_ut           inheritance
		    ), {
		T_QUIET; T_ASSERT_FALSE(remap_called, "Check that we're not remapping twice");
		remap_called = true;
		*address = nested_context_remapped;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(mach_vm_deallocate_kernel, kern_return_t,
	    (
		    vm_map_t target,
		    mach_vm_address_t address,
		    mach_vm_size_t size
	    ), {
		T_QUIET; T_ASSERT_FALSE(deallocate_called, "Check that we're not deallocating twice");
		deallocate_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_wire_kernel, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    vm_prot_ut              prot_u,
		    vm_tag_t                tag,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(wire_called, "Check that we're not wiring twice");
		T_QUIET; T_ASSERT_EQ_PTR(map, kernel_map, "Check wire target space");
		T_QUIET; T_ASSERT_EQ(start_u, nested_context_remapped, "Check wire context address");
		T_QUIET; T_ASSERT_EQ(end_u, nested_context_remapped + sizeof(arm_guest_context_t), "Check wire context size");
		wire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_unwire, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(unwire_called, "Check that we're not unwiring twice");
		T_QUIET; T_ASSERT_EQ_PTR(map, kernel_map, "Check unwire target space");
		T_QUIET; T_ASSERT_EQ(start_u, nested_context_remapped, "Check unwire context address");
		T_QUIET; T_ASSERT_EQ(end_u, nested_context_remapped + sizeof(arm_guest_context_t), "Check unwire context size");
		unwire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_find_entry_sh_locked, kern_return_t,
	    (
		    vm_map_find_lock_ctx_t  vml_ctx,
		    vm_map_t               * map,
		    vm_map_address_t        addr,
		    vmrl_find_sh_flags_t    flags), {
		return KERN_FAILURE;
	});

	T_MOCK_SET_CALLBACK(vm_map_found_entry_sh_unlock, void,
	    (
		    vm_map_find_lock_ctx_t    vml_ctx,
		    vm_map_t                 * map), {});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_init(vcpu->host_context.guest_context, nested_context_ipa);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_ERROR, "Root guest should receive error");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, 0);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_TRUE(remap_called, "Check that we've remapped the nested context");
	T_EXPECT_TRUE(deallocate_called, "Check that we've unmapped the nested context");
	T_EXPECT_TRUE(wire_called, "Check that we've wired the nested context");
	T_EXPECT_TRUE(unwire_called, "Check that we've unwired the nested context");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_init_error_protecting_context, "Test error while protecting context in guest map")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static bool remap_called;
	static bool deallocate_called;
	static bool wire_called;
	static bool unwire_called;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static uint64_t nested_context_ipa = 0x4000;
	static uint64_t nested_context_remapped = 0x100000000;
	static struct vm_map_entry fake_entry = {.protection = VM_PROT_READ};

	T_MOCK_SET_CALLBACK(mach_vm_remap_new_kernel, kern_return_t, (
		    vm_map_t                target_map,
		    mach_vm_offset_ut      * address,
		    mach_vm_size_ut         size,
		    mach_vm_offset_ut       mask,
		    vm_map_kernel_flags_t   vmk_flags,
		    vm_map_t                src_map,
		    mach_vm_offset_ut       memory_address,
		    boolean_t               copy,
		    vm_prot_ut             * cur_protection,
		    vm_prot_ut             * max_protection,
		    vm_inherit_ut           inheritance
		    ), {
		T_QUIET; T_ASSERT_FALSE(remap_called, "Check that we're not remapping twice");
		remap_called = true;
		*address = nested_context_remapped;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(mach_vm_deallocate_kernel, kern_return_t,
	    (
		    vm_map_t target,
		    mach_vm_address_t address,
		    mach_vm_size_t size
	    ), {
		T_QUIET; T_ASSERT_FALSE(deallocate_called, "Check that we're not deallocating twice");
		deallocate_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_wire_kernel, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    vm_prot_ut              prot_u,
		    vm_tag_t                tag,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(wire_called, "Check that we're not wiring twice");
		wire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_unwire, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(unwire_called, "Check that we're not unwiring twice");
		unwire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_find_entry_sh_locked, kern_return_t,
	    (
		    vm_map_find_lock_ctx_t  vml_ctx,
		    vm_map_t               * map,
		    vm_map_address_t        addr,
		    vmrl_find_sh_flags_t    flags), {
		vml_ctx->vmlc_vme = &fake_entry;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_found_entry_sh_unlock, void,
	    (
		    vm_map_find_lock_ctx_t    vml_ctx,
		    vm_map_t                 * map), {});

	T_MOCK_SET_RETVAL(mach_vm_protect, kern_return_t, KERN_NO_SPACE);

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_init(vcpu->host_context.guest_context, nested_context_ipa);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_ERROR, "Root guest should receive error");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, 0);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_TRUE(remap_called, "Check that we've remapped the nested context");
	T_EXPECT_TRUE(deallocate_called, "Check that we've unmapped the nested context");
	T_EXPECT_TRUE(wire_called, "Check that we've wired the nested context");
	T_EXPECT_TRUE(unwire_called, "Check that we've unwired the nested context");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_init_error_no_vm, "Test nested vCPU initialization failure when there is no VM")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	__block int vmenter_count = 0;
	__block uint64_t nested_context_ipa = 0x4000;
	__block struct vm_map_entry fake_entry = {.protection = VM_PROT_READ};

	T_MOCK_SET_RETVAL(vm_map_wire_kernel, kern_return_t, KERN_SUCCESS);
	T_MOCK_SET_RETVAL(vm_map_unwire, kern_return_t, KERN_SUCCESS);
	T_MOCK_SET_RETVAL(mach_vm_protect, kern_return_t, KERN_SUCCESS);
	T_MOCK_SET_RETVAL(mach_vm_deallocate_kernel, kern_return_t, KERN_SUCCESS);

	T_MOCK_SET_CALLBACK(mach_vm_remap_new_kernel, kern_return_t, (
		    vm_map_t                target_map,
		    mach_vm_offset_ut      * address,
		    mach_vm_size_ut         size,
		    mach_vm_offset_ut       mask,
		    vm_map_kernel_flags_t   vmk_flags,
		    vm_map_t                src_map,
		    mach_vm_offset_ut       memory_address,
		    boolean_t               copy,
		    vm_prot_ut             * cur_protection,
		    vm_prot_ut             * max_protection,
		    vm_inherit_ut           inheritance
		    ), {
		arm_guest_context_t *nested_context = checked_alloc_align(sizeof(arm_guest_context_t), PAGE_SIZE);
		T_QUIET; T_ASSERT_NOTNULL(nested_context, "Failed to allocate nested context");
		*address = (mach_vm_offset_ut) nested_context;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_find_entry_sh_locked, kern_return_t,
	    (
		    vm_map_find_lock_ctx_t  vml_ctx,
		    vm_map_t               * map,
		    vm_map_address_t        addr,
		    vmrl_find_sh_flags_t    flags), {
		vml_ctx->vmlc_vme = &fake_entry;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_found_entry_sh_unlock, void,
	    (
		    vm_map_find_lock_ctx_t    vml_ctx,
		    vm_map_t                 * map), {});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;
		hv_nested_vm_t *nvm = vcpu->vm->nested_vms[nested_vm_id];
		hv_nested_vcpu_t *nested_vcpu = &nvm->vcpu_byid[0];

		switch (vmenter_count) {
		case 1:
			nvm->space = MACH_PORT_NULL;
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");
			mock_nested_vcpu_init(vcpu->host_context.guest_context, nested_context_ipa);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_NO_DEVICE, "vCPU initialization should fail: no VM");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	// Intentionally skip setup_nested_vcpu and let the real code create the nested vCPU.

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_init_success, "Test nested vCPU initialization")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count = 0;
	static bool remap_called;
	static bool wire_called;
	static bool protect_called;
	static uint64_t nested_context_ipa = 0x4000;
	static uint64_t nested_context_remapped = 0x100000000;
	static struct vm_map_entry fake_entry = {.protection = VM_PROT_READ};

	T_MOCK_SET_CALLBACK(mach_vm_remap_new_kernel, kern_return_t, (
		    vm_map_t                target_map,
		    mach_vm_offset_ut      * address,
		    mach_vm_size_ut         size,
		    mach_vm_offset_ut       mask,
		    vm_map_kernel_flags_t   vmk_flags,
		    vm_map_t                src_map,
		    mach_vm_offset_ut       memory_address,
		    boolean_t               copy,
		    vm_prot_ut             * cur_protection,
		    vm_prot_ut             * max_protection,
		    vm_inherit_ut           inheritance
		    ), {
		T_QUIET; T_ASSERT_FALSE(remap_called, "Check that we're not remapping twice");
		remap_called = true;
		arm_guest_context_t *nested_context = aligned_alloc(PAGE_SIZE, sizeof(arm_guest_context_t));
		T_QUIET; T_ASSERT_NOTNULL(nested_context, "Failed to allocate nested context");
		memset(nested_context, 0, sizeof(arm_guest_context_t));
		*address = (mach_vm_offset_ut) nested_context;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_wire_kernel, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    vm_prot_ut              prot_u,
		    vm_tag_t                tag,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(wire_called, "Check that we're not wiring twice");
		wire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_find_entry_sh_locked, kern_return_t,
	    (
		    vm_map_find_lock_ctx_t  vml_ctx,
		    vm_map_t               * map,
		    vm_map_address_t        addr,
		    vmrl_find_sh_flags_t    flags), {
		vml_ctx->vmlc_vme = &fake_entry;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_found_entry_sh_unlock, void,
	    (
		    vm_map_find_lock_ctx_t    vml_ctx,
		    vm_map_t                 * map), {});

	T_MOCK_SET_CALLBACK(mach_vm_protect, kern_return_t, (
		    vm_map_t                map,
		    mach_vm_address_ut      start_u,
		    mach_vm_size_ut         size_u,
		    boolean_t               set_maximum,
		    vm_prot_ut              new_protection_u), {
		T_QUIET; T_ASSERT_FALSE(protect_called, "Check that we're not protecting twice");
		protect_called = true;
		return KERN_SUCCESS;
	});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;
		hv_nested_vcpu_t *nested_vcpu = &vcpu->vm->nested_vms[nested_vm_id]->vcpu_byid[0];

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");
			mock_nested_vcpu_init(vcpu->host_context.guest_context, nested_context_ipa);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "vCPU initialization should succeed");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	// Intentionally skip setup_nested_vcpu and let the real code create the nested vCPU.

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_TRUE(remap_called, "Check that we've remapped the nested context");
	T_EXPECT_TRUE(wire_called, "Check that we've wired the nested context");
	T_EXPECT_TRUE(protect_called, "Check that we've protected the nested context");

	hv_nested_vcpu_t *nested_vcpu = &vcpu->vm->nested_vms[nested_vm_id]->vcpu_byid[0];
	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_destroy_error_protecting_context, "Test error while protecting context in guest map")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static bool unwire_called;
	static bool deallocate_called;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	T_MOCK_SET_RETVAL(mach_vm_protect, kern_return_t, KERN_NO_SPACE);

	T_MOCK_SET_CALLBACK(vm_map_unwire, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(unwire_called, "Check that we're not unwiring twice");
		unwire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(mach_vm_deallocate_kernel, kern_return_t,
	    (
		    vm_map_t target,
		    mach_vm_address_t address,
		    mach_vm_size_t size
	    ), {
		T_QUIET; T_ASSERT_FALSE(deallocate_called, "Check that we're not deallocating twice");
		T_QUIET; T_ASSERT_EQ_PTR(target, kernel_map, "Check deallocate target space");
		T_QUIET; T_ASSERT_EQ(address, (uint64_t)nested_vcpu->kif, "Check deallocate address");
		T_QUIET; T_ASSERT_EQ((size_t)size, sizeof(arm_guest_context_t), "Check deallocate size");
		deallocate_called = true;
		return KERN_SUCCESS;
	});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_destroy(vcpu->host_context.guest_context);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_ERROR, "Root guest should receive error");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_TRUE(unwire_called, "Check that we've unwired the nested context");
	T_EXPECT_TRUE(deallocate_called, "Check that we've unmapped the nested context");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_destroy_success, "Test nested vCPU destruction")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static bool protect_called;
	static bool unwire_called;
	static bool deallocate_called;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	T_MOCK_SET_CALLBACK(mach_vm_protect, kern_return_t, (
		    vm_map_t                map,
		    mach_vm_address_ut      start_u,
		    mach_vm_size_ut         size_u,
		    boolean_t               set_maximum,
		    vm_prot_ut              new_protection_u), {
		T_QUIET; T_ASSERT_FALSE(protect_called, "Check that we're not protecting twice");
		T_QUIET; T_ASSERT_EQ_PTR(map, vcpu->host_context.guest_map, "Check protect target space");
		T_QUIET; T_ASSERT_EQ(start_u, nested_ro_context_ipa, "Check protect start address");
		T_QUIET; T_ASSERT_EQ(size_u, (uint64_t)sizeof(arm_guest_ro_context_t), "Check protect size");
		T_QUIET; T_ASSERT_EQ(new_protection_u, nested_ro_context_prot, "Check protect permissions");
		protect_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(vm_map_unwire, kern_return_t,
	    (
		    vm_map_t                map,
		    vm_map_offset_ut        start_u,
		    vm_map_offset_ut        end_u,
		    boolean_t               user_wire), {
		T_QUIET; T_ASSERT_FALSE(unwire_called, "Check that we're not unwiring twice");
		unwire_called = true;
		return KERN_SUCCESS;
	});

	T_MOCK_SET_CALLBACK(mach_vm_deallocate_kernel, kern_return_t,
	    (
		    vm_map_t target,
		    mach_vm_address_t address,
		    mach_vm_size_t size
	    ), {
		T_QUIET; T_ASSERT_FALSE(deallocate_called, "Check that we're not deallocating twice");
		deallocate_called = true;
		return KERN_SUCCESS;
	});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_destroy(vcpu->host_context.guest_context);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "vCPU destruction should succeed");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_TRUE(protect_called, "Check that we've unmapped the nested context");
	T_EXPECT_TRUE(unwire_called, "Check that we've unwired the nested context");
	T_EXPECT_TRUE(deallocate_called, "Check that we've unmapped the nested context");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_INVALID, "Nested vCPU should be invalid");

	free_mock_vcpu(vcpu);
}

T_DECL(root_vcpu_run_cancel_while_running_nested, "Test root vCPU cancellation while running nested vCPU")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			// Mock a root vCPU cancellation from another thread.
			os_atomic_store(&vcpu->vm->vcpu_byid[0].notified, true, relaxed);
			// Mock reception of the IPI.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_FIQ;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_EQ(vcpu->host_context.guest_context->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check vmexit reason");
	T_EXPECT_FALSE(os_atomic_load(&vcpu->vm->vcpu_byid[0].notified, relaxed),
	    "Check that the cancellation is no longer pending");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vcpu_run_cancel_before_running, "Test nested vCPU cancellation before vCPU is run")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run_cancel(vcpu->host_context.guest_context);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_TRUE(nested_vcpu->notified, "Check that the nested cancellation is pending");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 3:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Check nested run return value");
			T_EXPECT_EQ(nested_vcpu->kif->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check nested vmexit reason");
			T_EXPECT_EQ((uint64_t)nested_vcpu->kif->ro.exit.vmexit_reason,
			vcpu->host_context.guest_context->rw.regs.x[1], "Check nested vmexit consistency");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 3, "Check number of vmenters");
	T_EXPECT_EQ(vcpu->host_context.guest_context->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check vmexit reason");
	T_EXPECT_FALSE(nested_vcpu->notified, "Check that the nested cancellation is no longer pending");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

hv_return_t
hv_handle_nested_vcpu_run_cancel(hv_vcpu_t *vcpu, uint64_t nested_vm_id, uint64_t nested_vcpu_mask);

T_DECL(nested_vcpu_run_cancel_while_running, "Test nested vCPU cancellation while vCPU is run")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;
	static const uint64_t nested_vcpu_mask = 1ull << nested_vcpu_id;

	// Mock completion of IPI signalling.
	T_MOCK_SET_RETVAL(cpu_signal, kern_return_t, KERN_SUCCESS);

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			// The cancellation would normally be requested by another root vCPU, but for simplicity
			// let's just call straight into the underlying cancel implementation while the nested
			// vCPU is running.
			hv_handle_nested_vcpu_run_cancel(vcpu, 0, nested_vcpu_mask);
			T_EXPECT_TRUE(nested_vcpu->notified, "Check that the nested cancellation is pending");
			// Mock reception of the IPI.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_FIQ;
			break;

		case 3:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Check nested run return value");
			T_EXPECT_EQ(nested_vcpu->kif->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check nested vmexit reason");
			T_EXPECT_EQ((uint64_t)nested_vcpu->kif->ro.exit.vmexit_reason,
			vcpu->host_context.guest_context->rw.regs.x[1], "Check nested vmexit consistency");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 3, "Check number of vmenters");
	T_EXPECT_EQ(vcpu->host_context.guest_context->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check vmexit reason");
	T_EXPECT_FALSE(nested_vcpu->notified, "Check that the nested cancellation is no longer pending");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(concurrent_root_and_nested_cancellation, "Test concurrent root and nested cancellations")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	static int vmenter_count;
	static hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;
	static const uint64_t nested_vcpu_mask = 1ull << nested_vcpu_id;

	// Mock completion of IPI signalling.
	T_MOCK_SET_RETVAL(cpu_signal, kern_return_t, KERN_SUCCESS);

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 2:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			// Mock arrival of two concurrent cancellations, one for the root vCPU and the other for
			// the nested vCPU. We expect the former to be served first.
			os_atomic_store(&vcpu->vm->vcpu_byid[0].notified, true, relaxed);
			hv_handle_nested_vcpu_run_cancel(vcpu, 0, nested_vcpu_mask);
			// Simulate an IPI (FIQ) arriving while running the nested guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_FIQ;
			break;

		case 3:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Check nested run return value");
			T_EXPECT_EQ(nested_vcpu->kif->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check nested vmexit reason");
			T_EXPECT_EQ((uint64_t)nested_vcpu->kif->ro.exit.vmexit_reason,
			vcpu->host_context.guest_context->rw.regs.x[1], "Check nested vmexit consistency");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			break;

		case 4:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			// Mock a nested guest taking a synchronous exception to be routed to the root guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
			break;

		case 5:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Check nested run return value");
			T_EXPECT_EQ(nested_vcpu->kif->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_SYNC, "Check nested vmexit reason");
			T_EXPECT_EQ((uint64_t)nested_vcpu->kif->ro.exit.vmexit_reason,
			vcpu->host_context.guest_context->rw.regs.x[1], "Check nested vmexit consistency");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 2, "Check number of vmenters");
	T_EXPECT_EQ(vcpu->host_context.guest_context->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check vmexit reason");
	T_EXPECT_FALSE(vcpu->vm->vcpu_byid[0].notified, "Check that the root cancellation is served");
	T_EXPECT_FALSE(nested_vcpu->notified, "Check that the nested cancellation is served");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	result = hv_trap_vcpu_run(nested_vcpu_id);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 5, "Check number of vmenters");
	T_EXPECT_EQ(vcpu->host_context.guest_context->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check vmexit reason");
	T_EXPECT_FALSE(vcpu->vm->vcpu_byid[0].notified, "Check that the root cancellation is served");
	T_EXPECT_FALSE(nested_vcpu->notified, "Check that the nested cancellation is served");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

static void
root_vtimer_expiry_test(uint64_t cntv_ctl_el0, uint64_t timer_controls)
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	const uint64_t initial_host_hw_time = 10000;
	const uint64_t guest_timer_offset = 1000;
	const uint64_t guest_timer_deadline = 20050;
	const uint64_t wait_interval = guest_timer_deadline - initial_host_hw_time + guest_timer_offset;
	const uint64_t ticks_per_vmenter = 1000;
	static_assert((wait_interval % ticks_per_vmenter) != 0,
	    "wait_interval must not be a clean multiple of ticks_per_vmenter");
	const unsigned vmenters_to_deadline = (wait_interval / ticks_per_vmenter) + 1;
	const bool expect_root_timer_interrupt =
	    (cntv_ctl_el0 & (CNTV_CTL_EL0_ENABLE | CNTV_CTL_EL0_IMASKED)) ==
	    CNTV_CTL_EL0_ENABLE && (timer_controls & HV_TIMER_MASK) == 0;
	// One vmenter to schedule the nested guest, another one when the nested guest is preempted.
	const unsigned expected_root_vmenters = 2;
	// After accounting for the initial vmenter to schedule the nested guest, use many vmenters as
	// the timer allows, plus an additional one if the timer interrupt is disabled.
	const unsigned expected_nested_vmenters =
	    expect_root_timer_interrupt ? (vmenters_to_deadline - 1) : vmenters_to_deadline;
	// HW model.
	__block struct {
		uint64_t cntvct_el0;
		uint64_t guest_cntv_ctl_el0;
	} hw = {
		.cntvct_el0 = initial_host_hw_time
	};

	// Mock completion of IPI signalling.
	T_MOCK_SET_RETVAL(cpu_signal, kern_return_t, KERN_SUCCESS);

	/* BEGIN IGNORE CODESTYLE */
	T_MOCK_SET_CALLBACK(testable_arm_rsr64, uint64_t, (const char *regname), {
		if (!strcmp(regname, "ACNTVCT_EL0") || !strcmp(regname, "S3_4_C15_C10_6")
			|| !strcmp(regname, "CNTVCTSS_EL0")) {
			return hw.cntvct_el0;
		}
		if (!strcmp(regname, "CNTV_CTL_EL02")) {
			return hw.guest_cntv_ctl_el0;
		}
		return 0;
	});

	T_MOCK_SET_CALLBACK(testable_arm_wsr64, void, (const char *regname, uint64_t value), {
		if (!strcmp(regname, "CNTV_CTL_EL02")) {
			hw.guest_cntv_ctl_el0 = value;
		}
	});
	/* END IGNORE CODESTYLE */

	vcpu->kif->ro.controls.virtual_timer_offset = guest_timer_offset;
	vcpu->kif->rw.banked_sysregs.cntv_cval_el0 = guest_timer_deadline;
	vcpu->kif->rw.banked_sysregs.cntv_ctl_el0 = cntv_ctl_el0;
	vcpu->kif->rw.controls.timer = timer_controls;

	__block int vmenter_count = 0;
	__block hv_nested_vcpu_t *nested_vcpu = NULL;
	static const uint64_t nested_vcpu_id = 0;
	static const uint64_t nested_vcpu_mask = 1ull << nested_vcpu_id;
	__block unsigned nested_vmenters = 0;
	__block unsigned root_vmenters = 0;
	// Mock hv_enter_guest to simulate different execution phases
	/* BEGIN IGNORE CODESTYLE */
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		if (vmenter_count == 1 || vmenter_count == expected_nested_vmenters + 2) {
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			root_vmenters++;
		} else {
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu);
			nested_vmenters++;
		}

		const bool in_nested = vcpu->nested_vcpu != NULL;
		if (in_nested) {
			if (!expect_root_timer_interrupt && nested_vmenters == expected_nested_vmenters) {
				// Mock a nested guest cancellation so that we return to the root guest.
				hv_handle_nested_vcpu_run_cancel(vcpu, 0, nested_vcpu_mask);
				vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			}
			// Simulate an IPI (FIQ) arriving while running the nested guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_FIQ;
		} else {
			if (root_vmenters == 1) {
				mock_nested_vcpu_run(vcpu->host_context.guest_context, nested_vcpu_id);
			} else {
				// If the timer interrupt is expected, host xnu should preempt the nested guest and
				// set the exit reason to HOST_AST to give guest xnu a chance to serve its ASTs.
				const uint32_t expected_reason = expect_root_timer_interrupt ?
					ARM_VMEXIT_REASON_HOST_AST : ARM_VMEXIT_REASON_NONE;
				T_EXPECT_EQ(nested_vcpu->kif->ro.exit.vmexit_reason, expected_reason, "Check vmexit reason");
				T_EXPECT_EQ((uint64_t)nested_vcpu->kif->ro.exit.vmexit_reason,
				    vcpu->host_context.guest_context->rw.regs.x[1], "Check nested vmexit consistency");
				// Mock a root guest cancellation so that we return to host userspace.
				vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			}
		}

		T_ASSERT_LE(nested_vmenters, expected_nested_vmenters, "Check current number of nested vmenters");
		T_ASSERT_LE(root_vmenters, expected_root_vmenters, "Check current number of root vmenters");
		hw.cntvct_el0 += ticks_per_vmenter;
	});
	/* END IGNORE CODESTYLE */

	nested_vcpu = setup_nested_vcpu(vcpu, nested_vcpu_id);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(nested_vmenters, expected_nested_vmenters, "Check number of nested vmenters");
	T_EXPECT_EQ(root_vmenters, expected_root_vmenters, "Check number of root vmenters");
	T_EXPECT_EQ(vcpu->host_context.guest_context->ro.exit.vmexit_reason, ARM_VMEXIT_REASON_NONE, "Check vmexit reason");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(root_vtimer_expiry_interrupt, "Test root vCPU vtimer expiration interrupt")
{
	root_vtimer_expiry_test(CNTV_CTL_EL0_ENABLE, 0);
}

T_DECL(root_vtimer_expiry_hw_enabled_sw_masked, "Test root vCPU vtimer expiration with the SW interrupt masked")
{
	root_vtimer_expiry_test(CNTV_CTL_EL0_ENABLE, HV_TIMER_MASK);
}

T_DECL(root_vtimer_expiry_hw_masked_sw_enabled, "Test root vCPU vtimer expiration with the HW interrupt masked")
{
	root_vtimer_expiry_test(CNTV_CTL_EL0_ENABLE | CNTV_CTL_EL0_IMASKED, 0);
}

T_DECL(root_vtimer_expiry_hw_masked_sw_masked, "Test root vCPU vtimer expiration with the HW and SW interrupt masked")
{
	root_vtimer_expiry_test(CNTV_CTL_EL0_ENABLE | CNTV_CTL_EL0_IMASKED, HV_TIMER_MASK);
}

T_DECL(root_vtimer_expiry_hw_disabled_masked_sw_enabled,
    "Test root vCPU vtimer expiration with the HW interrupt disabled and masked")
{
	root_vtimer_expiry_test(CNTV_CTL_EL0_IMASKED, 0);
}

T_DECL(root_vtimer_expiry_hw_disabled_masked_sw_masked,
    "Test root vCPU vtimer expiration with the HW interrupt disabled and masked and SW interrupt masked")
{
	root_vtimer_expiry_test(CNTV_CTL_EL0_IMASKED, HV_TIMER_MASK);
}

T_DECL(root_vtimer_expiry_hw_disabled_sw_enabled, "Test root vCPU vtimer expiration with the interrupt disabled")
{
	root_vtimer_expiry_test(0, 0);
}

T_DECL(root_vtimer_expiry_hw_disabled_sw_masked,
    "Test root vCPU vtimer expiration with the interrupt disabled and SW interrupt masked")
{
	root_vtimer_expiry_test(0, HV_TIMER_MASK);
}

T_DECL(tlb_flush_on_nested_vcpu_switch, "Test TLB flushing when different nested vCPUs are scheduled on the same pCPU")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	__block int vmenter_count = 0;
	__block hv_nested_vcpu_t *nested_vcpu0;
	__block hv_nested_vcpu_t *nested_vcpu1;

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu0->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(nested_vcpu1->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_FALSE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, 0);
			break;

		case 2:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu0);
			T_EXPECT_FALSE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			// Mock a nested guest taking a synchronous exception to be routed to the root guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
			break;

		case 3:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu0->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(nested_vcpu1->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_FALSE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, 0);
			break;

		case 4:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu0);
			T_EXPECT_FALSE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			// Mock a nested guest taking a synchronous exception to be routed to the root guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
			break;

		case 5:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu0->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(nested_vcpu1->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_FALSE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			mock_nested_vcpu_run(vcpu->host_context.guest_context, 1);
			break;

		case 6:
			assert_vcpu_in_nested_guest(vcpu, nested_vcpu1);
			T_EXPECT_TRUE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			// Mock a nested guest taking a synchronous exception to be routed to the root guest.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_SYNC;
			break;

		case 7:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(nested_vcpu0->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_QUIET; T_ASSERT_EQ(nested_vcpu1->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
			T_EXPECT_FALSE(vcpu->host_context.flush_local_tlb, "Check pending TLB flush");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	nested_vcpu0 = setup_nested_vcpu(vcpu, 0);
	nested_vcpu1 = setup_nested_vcpu(vcpu, 1);

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 7, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);
	T_QUIET; T_ASSERT_EQ(nested_vcpu0->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");
	T_QUIET; T_ASSERT_EQ(nested_vcpu1->state, NESTED_VCPU_IDLE, "Nested vCPU should be idle");

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vm_init, "Test nested VM init")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	__block int vmenter_count;
	__block bool return_no_resources = false;

	/* BEGIN IGNORE CODESTYLE */
	T_MOCK_SET_CALLBACK(hv_space_create, hv_return_t, (hv_vm_t * vm, uint64_t min_ipa, uint64_t ipa_size, uint32_t granule, uint64_t * out_asid), {
		if (return_no_resources) {
			return HV_NO_RESOURCES;
		} else {
			*out_asid = mock_nested_asid;
			return HV_SUCCESS;
		}
	});
	/* END IGNORE CODESTYLE */

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;
		hv_nested_vm_t *nested_vm = vcpu->vm->nested_vms[nested_vm_id];
		const uint64_t min_ipa = 0x100000000;
		const uint64_t ipa_size = 0x100000000;
		const uint64_t granule = 16 * 1024;
		const hv_vm_isa_t isa = _HV_VM_ISA_GENERIC;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			mock_nested_vm_init(vcpu->host_context.guest_context, min_ipa, ipa_size, 0x1000000000000000ull /* invalid */, _HV_VM_ISA_GENERIC);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_BAD_ARGUMENT, "Error: invalid granule size");
			T_QUIET; T_ASSERT_TRUE(!hv_is_nested_vm_valid(nested_vm), "Nested VM should be invalid");
			return_no_resources = true;
			mock_nested_vm_init(vcpu->host_context.guest_context, min_ipa, ipa_size, granule, isa);
			break;

		case 3:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_NO_RESOURCES, "Error: hv_space_create returns HV_NO_RESOURCES");
			T_QUIET; T_ASSERT_TRUE(!hv_is_nested_vm_valid(nested_vm), "Nested VM should be invalid");
			return_no_resources = false;
			mock_nested_vm_init(vcpu->host_context.guest_context, min_ipa, ipa_size, granule, isa);
			break;

		case 4:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Success creating first nested VM");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[1], nested_vm_id, "Returned nested VM ID == 0");
			T_QUIET; T_ASSERT_TRUE(hv_is_nested_vm_valid(nested_vm), "Nested VM should be valid");
			mock_nested_vm_init(vcpu->host_context.guest_context, min_ipa, ipa_size, granule, isa);
			break;

		case 5:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Success creating second nested VM");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[1], nested_vm_id + 1, "Returned nested VM ID == 1");
			T_QUIET; T_ASSERT_TRUE(hv_is_nested_vm_valid(vcpu->vm->nested_vms[nested_vm_id + 1]), "Nested VM should be valid");
			// Simulate the scenario where all nested VM IDs are taken.
			bitmap_full(&vcpu->vm->nested_vm_id_online_mask[0], HV_NESTED_VM_MAX);
			mock_nested_vm_init(vcpu->host_context.guest_context, min_ipa, ipa_size, granule, isa);
			break;

		case 6:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_NO_RESOURCES, "Failure creating a nested VM: limit reached");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	vcpu->vm->nested_vms[nested_vm_id]->space = MACH_PORT_NULL; // Restore nested VM state back to INVALID

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 6, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);

	free_mock_vcpu(vcpu);
}

T_DECL(nested_vm_destroy, "Test nested VM destroy")
{
	hv_vcpu_t *vcpu = create_mock_vcpu();

	__block int vmenter_count;
	__block bool port_deallocate_called = false;

	T_MOCK_SET_CALLBACK(hv_space_create, hv_return_t, (hv_vm_t * vm, uint64_t min_ipa, uint64_t ipa_size, uint32_t granule, uint64_t * out_asid), {
		*out_asid = mock_nested_asid;
		return HV_SUCCESS;
	})

	T_MOCK_SET_CALLBACK(mach_port_deallocate, kern_return_t, (ipc_space_t space, mach_port_name_t name), {
		T_QUIET; T_EXPECT_FALSE(port_deallocate_called, "Check that we're not deallocating port twice");
		T_QUIET; T_EXPECT_EQ_PTR(space, current_space(), "Check port deallocate space");
		T_QUIET; T_EXPECT_EQ(name, (mach_port_name_t)mock_nested_asid, "Check port name being deallocated");
		port_deallocate_called = true;
		return KERN_SUCCESS;
	});

	// Mock hv_enter_guest to simulate different execution phases
	T_MOCK_SET_CALLBACK(hv_enter_guest, void, (arm_guest_context_t * guest_context, arm_host_context_t * host_context), {
		vmenter_count++;
		hv_nested_vm_t *nested_vm = vcpu->vm->nested_vms[nested_vm_id];
		const uint64_t min_ipa = 0x100000000;
		const uint64_t ipa_size = 0x100000000;
		const uint64_t granule = 16 * 1024;
		const hv_vm_isa_t isa = _HV_VM_ISA_GENERIC;

		switch (vmenter_count) {
		case 1:
			assert_vcpu_in_root_guest(vcpu);
			mock_nested_vm_destroy(vcpu->host_context.guest_context, HV_NESTED_VM_MAX);
			break;

		case 2:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_BAD_ARGUMENT, "Error: invalid nested VM ID");
			T_QUIET; T_ASSERT_TRUE(!hv_is_nested_vm_valid(nested_vm), "Nested VM should be invalid");
			mock_nested_vm_init(vcpu->host_context.guest_context, min_ipa, ipa_size, granule, isa);
			break;

		case 3:
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Successful creation");
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[1], nested_vm_id, "Returned nested VM ID == 0");
			T_QUIET; T_ASSERT_TRUE(hv_is_nested_vm_valid(nested_vm), "Nested VM should be valid");
			nested_vm->vcpu_byid[0].state = NESTED_VCPU_BUSY; // Fake presence of a VCPU
			mock_nested_vm_destroy(vcpu->host_context.guest_context, nested_vm_id);
			break;

		case 4:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_BUSY, "Error: VCPU exists");
			T_QUIET; T_ASSERT_TRUE(hv_is_nested_vm_valid(nested_vm), "Nested VM should be valid");
			nested_vm->vcpu_byid[0].state = NESTED_VCPU_INVALID; // Revert VCPU state so we can test successful destruction
			mock_nested_vm_destroy(vcpu->host_context.guest_context, nested_vm_id);
			break;

		case 5:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_SUCCESS, "Successful destruction!");
			T_QUIET; T_EXPECT_TRUE(port_deallocate_called, "Check that port was deallocated");
			T_QUIET; T_ASSERT_TRUE(!hv_is_nested_vm_valid(nested_vm), "Nested VM should be invalid");
			mock_nested_vm_destroy(vcpu->host_context.guest_context, nested_vm_id);
			break;

		case 6:
			assert_vcpu_in_root_guest(vcpu);
			T_QUIET; T_ASSERT_EQ(vcpu->host_context.guest_context->rw.regs.x[0], (uint64_t)HV_NO_DEVICE, "Error: cannot destroy non-existent VM");
			// Mock a root guest cancellation so that we return to host userspace.
			vcpu->host_context.guest_context->ro.exit.vmexit_reason = ARM_VMEXIT_REASON_NONE;
			break;

		default:
			T_FAIL("Unexpected number of vmenters: %d", vmenter_count);
			break;
		}
	});

	vcpu->vm->nested_vms[nested_vm_id]->space = MACH_PORT_NULL;  // Restore nested VM state back to INVALID

	hv_return_t result = hv_trap_vcpu_run(0);

	T_EXPECT_EQ(result, HV_SUCCESS, "Should succeed through the nested flow");
	T_EXPECT_EQ(vmenter_count, 6, "Check number of vmenters");

	assert_vcpu_in_root_guest(vcpu);

	free_mock_vcpu(vcpu);
}
