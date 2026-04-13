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

#pragma once

#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_cpu.h"
#include "mocks/osfmk/mock_hv.h"
#include "mocks/osfmk/mock_vm.h"
#include "mocks/osfmk/mock_vm_map.h"
#include "mocks/osfmk/mock_mach_port.h"

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

// Constants for mock vCPU creation
extern const uint64_t mock_nested_asid;
extern const hv_paranested_measurement_t shared_measurement;
extern const uint64_t nested_vm_id;

// Configuration structure for extensible mock vCPU creation
typedef struct mock_vcpu_config {
	bool paranested_initialized;
	bool paranested_enabled;
	hv_vm_isa_t isa;
} mock_vcpu_config_t;

// Helper functions for test setup
hv_vcpu_t *create_mock_vcpu(void);
hv_vcpu_t *create_mock_vcpu_ext(const mock_vcpu_config_t *config);
void free_mock_vcpu(hv_vcpu_t *vcpu);

// vCPU state assertion functions
void assert_vcpu_in_root_guest(hv_vcpu_t *vcpu);
void assert_vcpu_in_nested_guest(hv_vcpu_t *vcpu, hv_nested_vcpu_t *nested_vcpu);

// HVC mocking functions
void mock_nested_hvc(arm_guest_context_t *context, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4);
void mock_nested_vm_init(arm_guest_context_t *context, uint64_t min_ipa, uint64_t ipa_size, uint64_t granule, hv_vm_isa_t isa);
void mock_nested_vm_destroy(arm_guest_context_t *context, uint64_t vm_id);
void mock_nested_init(arm_guest_context_t *context, uint64_t measurement_pair_ipa, uint64_t measurement_pair_size);
void mock_context_version(arm_guest_context_t *context, uint16_t guest_min_version, uint16_t guest_max_version);
void mock_nested_vcpu_init(arm_guest_context_t *context, uint64_t nested_context_ipa);
void mock_nested_vcpu_run(arm_guest_context_t *context, uint64_t nested_vcpu_id);
void mock_nested_vcpu_run_cancel(arm_guest_context_t *context);
void mock_nested_vcpu_destroy(arm_guest_context_t *context);
void mock_hv_capabilities(arm_guest_context_t *context, uint64_t caps_buffer_ipa);

// Shared mock structures for nested guest mapping
extern struct pmap _nested_guest_pmap;
extern struct _vm_map _nested_guest_map;
extern vm_map_t mock_nested_guest_map;
