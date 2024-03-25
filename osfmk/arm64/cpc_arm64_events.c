// Copyright (c) 2023 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#include <arm64/cpc_arm64.h>
#include <kern/assert.h>
#include <kern/cpc.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct cpc_event {
	const char *cev_name;
	uint16_t cev_selector;
};

struct cpc_event_list {
	unsigned int cel_event_count;
	struct cpc_event cel_events[];
};

static const struct cpc_event_list _cpc_known_cpmu_events;
static const struct cpc_event_list _cpc_known_upmu_events = {
	.cel_event_count = 0,
	.cel_events = {},
};

const struct cpc_event_list *_cpc_known_events[CPC_HW_COUNT] = {
	[CPC_HW_CPMU] = &_cpc_known_cpmu_events,
	[CPC_HW_UPMU] = &_cpc_known_upmu_events,
};

static const struct cpc_event *
_cpc_select_event(cpc_hw_t hw, uint16_t selector)
{
	assert(hw < CPC_HW_COUNT);
	const struct cpc_event_list *list = _cpc_known_events[hw];
	for (unsigned int i = 0; i < list->cel_event_count; i++) {
		if (list->cel_events[i].cev_selector == selector) {
			return &list->cel_events[i];
		}
	}
	return NULL;
}

static
#if !CPC_INSECURE
const
#endif // !CPC_INSECURE
cpc_event_policy_t _cpc_event_policy = CPC_EVPOL_DEFAULT;

cpc_event_policy_t
cpc_get_event_policy(void)
{
	return _cpc_event_policy;
}

#if CPC_INSECURE

void
cpc_set_event_policy(cpc_event_policy_t new_policy)
{
	_cpc_event_policy = new_policy;
}

#endif // CPC_INSECURE

bool
cpc_event_allowed(
	cpc_hw_t hw,
	uint16_t event_selector)
{
	if (event_selector == 0) {
		return true;
	}
	switch (_cpc_event_policy) {
#if CPC_INSECURE
	case CPC_EVPOL_ALLOW_ALL:
		return true;
#endif // CPC_INSECURE
	case CPC_EVPOL_DENY_ALL:
		return false;
	case CPC_EVPOL_RESTRICT_TO_KNOWN:
		return _cpc_select_event(hw, event_selector) != NULL;
	}
	return false;
}

static const struct cpc_event_list _cpc_known_cpmu_events = {
#if   ARM64_BOARD_CONFIG_T6000
	.cel_event_count = 60,
	.cel_events = {
		{ .cev_selector = 0x0000, .cev_name = "NONE" },
		{ .cev_selector = 0x0001, .cev_name = "RETIRE_UOP" },
		{ .cev_selector = 0x0002, .cev_name = "CORE_ACTIVE_CYCLE" },
		{ .cev_selector = 0x0004, .cev_name = "L1I_TLB_FILL" },
		{ .cev_selector = 0x0005, .cev_name = "L1D_TLB_FILL" },
		{ .cev_selector = 0x0007, .cev_name = "MMU_TABLE_WALK_INSTRUCTION" },
		{ .cev_selector = 0x0008, .cev_name = "MMU_TABLE_WALK_DATA" },
		{ .cev_selector = 0x000a, .cev_name = "L2_TLB_MISS_INSTRUCTION" },
		{ .cev_selector = 0x000b, .cev_name = "L2_TLB_MISS_DATA" },
		{ .cev_selector = 0x000d, .cev_name = "MMU_VIRTUAL_MEMORY_FAULT_NONSPEC" },
		{ .cev_selector = 0x0052, .cev_name = "SCHEDULE_UOP" },
		{ .cev_selector = 0x006c, .cev_name = "INTERRUPT_PENDING" },
		{ .cev_selector = 0x0070, .cev_name = "MAP_STALL_DISPATCH" },
		{ .cev_selector = 0x0075, .cev_name = "MAP_REWIND" },
		{ .cev_selector = 0x0076, .cev_name = "MAP_STALL" },
		{ .cev_selector = 0x007c, .cev_name = "MAP_INT_UOP" },
		{ .cev_selector = 0x007d, .cev_name = "MAP_LDST_UOP" },
		{ .cev_selector = 0x007e, .cev_name = "MAP_SIMD_UOP" },
		{ .cev_selector = 0x0084, .cev_name = "FLUSH_RESTART_OTHER_NONSPEC" },
		{ .cev_selector = 0x008c, .cev_name = "INST_ALL" },
		{ .cev_selector = 0x008d, .cev_name = "INST_BRANCH" },
		{ .cev_selector = 0x008e, .cev_name = "INST_BRANCH_CALL" },
		{ .cev_selector = 0x008f, .cev_name = "INST_BRANCH_RET" },
		{ .cev_selector = 0x0090, .cev_name = "INST_BRANCH_TAKEN" },
		{ .cev_selector = 0x0093, .cev_name = "INST_BRANCH_INDIR" },
		{ .cev_selector = 0x0094, .cev_name = "INST_BRANCH_COND" },
		{ .cev_selector = 0x0095, .cev_name = "INST_INT_LD" },
		{ .cev_selector = 0x0096, .cev_name = "INST_INT_ST" },
		{ .cev_selector = 0x0097, .cev_name = "INST_INT_ALU" },
		{ .cev_selector = 0x0098, .cev_name = "INST_SIMD_LD" },
		{ .cev_selector = 0x0099, .cev_name = "INST_SIMD_ST" },
		{ .cev_selector = 0x009a, .cev_name = "INST_SIMD_ALU" },
		{ .cev_selector = 0x009b, .cev_name = "INST_LDST" },
		{ .cev_selector = 0x009c, .cev_name = "INST_BARRIER" },
		{ .cev_selector = 0x00a0, .cev_name = "L1D_TLB_ACCESS" },
		{ .cev_selector = 0x00a1, .cev_name = "L1D_TLB_MISS" },
		{ .cev_selector = 0x00a2, .cev_name = "L1D_CACHE_MISS_ST" },
		{ .cev_selector = 0x00a3, .cev_name = "L1D_CACHE_MISS_LD" },
		{ .cev_selector = 0x00a6, .cev_name = "LD_UNIT_UOP" },
		{ .cev_selector = 0x00a7, .cev_name = "ST_UNIT_UOP" },
		{ .cev_selector = 0x00a8, .cev_name = "L1D_CACHE_WRITEBACK" },
		{ .cev_selector = 0x00b1, .cev_name = "LDST_X64_UOP" },
		{ .cev_selector = 0x00b2, .cev_name = "LDST_XPG_UOP" },
		{ .cev_selector = 0x00b3, .cev_name = "ATOMIC_OR_EXCLUSIVE_SUCC" },
		{ .cev_selector = 0x00b4, .cev_name = "ATOMIC_OR_EXCLUSIVE_FAIL" },
		{ .cev_selector = 0x00bf, .cev_name = "L1D_CACHE_MISS_LD_NONSPEC" },
		{ .cev_selector = 0x00c0, .cev_name = "L1D_CACHE_MISS_ST_NONSPEC" },
		{ .cev_selector = 0x00c1, .cev_name = "L1D_TLB_MISS_NONSPEC" },
		{ .cev_selector = 0x00c4, .cev_name = "ST_MEMORY_ORDER_VIOLATION_NONSPEC" },
		{ .cev_selector = 0x00c5, .cev_name = "BRANCH_COND_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c6, .cev_name = "BRANCH_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c8, .cev_name = "BRANCH_RET_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00ca, .cev_name = "BRANCH_CALL_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00cb, .cev_name = "BRANCH_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00d4, .cev_name = "L1I_TLB_MISS_DEMAND" },
		{ .cev_selector = 0x00d6, .cev_name = "MAP_DISPATCH_BUBBLE" },
		{ .cev_selector = 0x00db, .cev_name = "L1I_CACHE_MISS_DEMAND" },
		{ .cev_selector = 0x00de, .cev_name = "FETCH_RESTART" },
		{ .cev_selector = 0x00e5, .cev_name = "ST_NT_UOP" },
		{ .cev_selector = 0x00e6, .cev_name = "LD_NT_UOP" },
	},
#elif ARM64_BOARD_CONFIG_T6020
	.cel_event_count = 59,
	.cel_events = {
		{ .cev_selector = 0x0000, .cev_name = "NONE" },
		{ .cev_selector = 0x0001, .cev_name = "RETIRE_UOP" },
		{ .cev_selector = 0x0002, .cev_name = "CORE_ACTIVE_CYCLE" },
		{ .cev_selector = 0x0004, .cev_name = "L1I_TLB_FILL" },
		{ .cev_selector = 0x0005, .cev_name = "L1D_TLB_FILL" },
		{ .cev_selector = 0x0007, .cev_name = "MMU_TABLE_WALK_INSTRUCTION" },
		{ .cev_selector = 0x0008, .cev_name = "MMU_TABLE_WALK_DATA" },
		{ .cev_selector = 0x000a, .cev_name = "L2_TLB_MISS_INSTRUCTION" },
		{ .cev_selector = 0x000b, .cev_name = "L2_TLB_MISS_DATA" },
		{ .cev_selector = 0x000d, .cev_name = "MMU_VIRTUAL_MEMORY_FAULT_NONSPEC" },
		{ .cev_selector = 0x006c, .cev_name = "INTERRUPT_PENDING" },
		{ .cev_selector = 0x0070, .cev_name = "MAP_STALL_DISPATCH" },
		{ .cev_selector = 0x0075, .cev_name = "MAP_REWIND" },
		{ .cev_selector = 0x0076, .cev_name = "MAP_STALL" },
		{ .cev_selector = 0x007c, .cev_name = "MAP_INT_UOP" },
		{ .cev_selector = 0x007d, .cev_name = "MAP_LDST_UOP" },
		{ .cev_selector = 0x007e, .cev_name = "MAP_SIMD_UOP" },
		{ .cev_selector = 0x0084, .cev_name = "FLUSH_RESTART_OTHER_NONSPEC" },
		{ .cev_selector = 0x008c, .cev_name = "INST_ALL" },
		{ .cev_selector = 0x008d, .cev_name = "INST_BRANCH" },
		{ .cev_selector = 0x008e, .cev_name = "INST_BRANCH_CALL" },
		{ .cev_selector = 0x008f, .cev_name = "INST_BRANCH_RET" },
		{ .cev_selector = 0x0090, .cev_name = "INST_BRANCH_TAKEN" },
		{ .cev_selector = 0x0093, .cev_name = "INST_BRANCH_INDIR" },
		{ .cev_selector = 0x0094, .cev_name = "INST_BRANCH_COND" },
		{ .cev_selector = 0x0095, .cev_name = "INST_INT_LD" },
		{ .cev_selector = 0x0096, .cev_name = "INST_INT_ST" },
		{ .cev_selector = 0x0097, .cev_name = "INST_INT_ALU" },
		{ .cev_selector = 0x0098, .cev_name = "INST_SIMD_LD" },
		{ .cev_selector = 0x0099, .cev_name = "INST_SIMD_ST" },
		{ .cev_selector = 0x009a, .cev_name = "INST_SIMD_ALU" },
		{ .cev_selector = 0x009b, .cev_name = "INST_LDST" },
		{ .cev_selector = 0x009c, .cev_name = "INST_BARRIER" },
		{ .cev_selector = 0x00a0, .cev_name = "L1D_TLB_ACCESS" },
		{ .cev_selector = 0x00a1, .cev_name = "L1D_TLB_MISS" },
		{ .cev_selector = 0x00a2, .cev_name = "L1D_CACHE_MISS_ST" },
		{ .cev_selector = 0x00a3, .cev_name = "L1D_CACHE_MISS_LD" },
		{ .cev_selector = 0x00a6, .cev_name = "LD_UNIT_UOP" },
		{ .cev_selector = 0x00a7, .cev_name = "ST_UNIT_UOP" },
		{ .cev_selector = 0x00a8, .cev_name = "L1D_CACHE_WRITEBACK" },
		{ .cev_selector = 0x00b1, .cev_name = "LDST_X64_UOP" },
		{ .cev_selector = 0x00b2, .cev_name = "LDST_XPG_UOP" },
		{ .cev_selector = 0x00b3, .cev_name = "ATOMIC_OR_EXCLUSIVE_SUCC" },
		{ .cev_selector = 0x00b4, .cev_name = "ATOMIC_OR_EXCLUSIVE_FAIL" },
		{ .cev_selector = 0x00bf, .cev_name = "L1D_CACHE_MISS_LD_NONSPEC" },
		{ .cev_selector = 0x00c0, .cev_name = "L1D_CACHE_MISS_ST_NONSPEC" },
		{ .cev_selector = 0x00c1, .cev_name = "L1D_TLB_MISS_NONSPEC" },
		{ .cev_selector = 0x00c4, .cev_name = "ST_MEMORY_ORDER_VIOLATION_NONSPEC" },
		{ .cev_selector = 0x00c5, .cev_name = "BRANCH_COND_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c6, .cev_name = "BRANCH_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c8, .cev_name = "BRANCH_RET_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00ca, .cev_name = "BRANCH_CALL_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00cb, .cev_name = "BRANCH_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00d4, .cev_name = "L1I_TLB_MISS_DEMAND" },
		{ .cev_selector = 0x00d6, .cev_name = "MAP_DISPATCH_BUBBLE" },
		{ .cev_selector = 0x00db, .cev_name = "L1I_CACHE_MISS_DEMAND" },
		{ .cev_selector = 0x00de, .cev_name = "FETCH_RESTART" },
		{ .cev_selector = 0x00e5, .cev_name = "ST_NT_UOP" },
		{ .cev_selector = 0x00e6, .cev_name = "LD_NT_UOP" },
	},
#elif ARM64_BOARD_CONFIG_T8101
	.cel_event_count = 60,
	.cel_events = {
		{ .cev_selector = 0x0000, .cev_name = "NONE" },
		{ .cev_selector = 0x0001, .cev_name = "RETIRE_UOP" },
		{ .cev_selector = 0x0002, .cev_name = "CORE_ACTIVE_CYCLE" },
		{ .cev_selector = 0x0004, .cev_name = "L1I_TLB_FILL" },
		{ .cev_selector = 0x0005, .cev_name = "L1D_TLB_FILL" },
		{ .cev_selector = 0x0007, .cev_name = "MMU_TABLE_WALK_INSTRUCTION" },
		{ .cev_selector = 0x0008, .cev_name = "MMU_TABLE_WALK_DATA" },
		{ .cev_selector = 0x000a, .cev_name = "L2_TLB_MISS_INSTRUCTION" },
		{ .cev_selector = 0x000b, .cev_name = "L2_TLB_MISS_DATA" },
		{ .cev_selector = 0x000d, .cev_name = "MMU_VIRTUAL_MEMORY_FAULT_NONSPEC" },
		{ .cev_selector = 0x0052, .cev_name = "SCHEDULE_UOP" },
		{ .cev_selector = 0x006c, .cev_name = "INTERRUPT_PENDING" },
		{ .cev_selector = 0x0070, .cev_name = "MAP_STALL_DISPATCH" },
		{ .cev_selector = 0x0075, .cev_name = "MAP_REWIND" },
		{ .cev_selector = 0x0076, .cev_name = "MAP_STALL" },
		{ .cev_selector = 0x007c, .cev_name = "MAP_INT_UOP" },
		{ .cev_selector = 0x007d, .cev_name = "MAP_LDST_UOP" },
		{ .cev_selector = 0x007e, .cev_name = "MAP_SIMD_UOP" },
		{ .cev_selector = 0x0084, .cev_name = "FLUSH_RESTART_OTHER_NONSPEC" },
		{ .cev_selector = 0x008c, .cev_name = "INST_ALL" },
		{ .cev_selector = 0x008d, .cev_name = "INST_BRANCH" },
		{ .cev_selector = 0x008e, .cev_name = "INST_BRANCH_CALL" },
		{ .cev_selector = 0x008f, .cev_name = "INST_BRANCH_RET" },
		{ .cev_selector = 0x0090, .cev_name = "INST_BRANCH_TAKEN" },
		{ .cev_selector = 0x0093, .cev_name = "INST_BRANCH_INDIR" },
		{ .cev_selector = 0x0094, .cev_name = "INST_BRANCH_COND" },
		{ .cev_selector = 0x0095, .cev_name = "INST_INT_LD" },
		{ .cev_selector = 0x0096, .cev_name = "INST_INT_ST" },
		{ .cev_selector = 0x0097, .cev_name = "INST_INT_ALU" },
		{ .cev_selector = 0x0098, .cev_name = "INST_SIMD_LD" },
		{ .cev_selector = 0x0099, .cev_name = "INST_SIMD_ST" },
		{ .cev_selector = 0x009a, .cev_name = "INST_SIMD_ALU" },
		{ .cev_selector = 0x009b, .cev_name = "INST_LDST" },
		{ .cev_selector = 0x009c, .cev_name = "INST_BARRIER" },
		{ .cev_selector = 0x00a0, .cev_name = "L1D_TLB_ACCESS" },
		{ .cev_selector = 0x00a1, .cev_name = "L1D_TLB_MISS" },
		{ .cev_selector = 0x00a2, .cev_name = "L1D_CACHE_MISS_ST" },
		{ .cev_selector = 0x00a3, .cev_name = "L1D_CACHE_MISS_LD" },
		{ .cev_selector = 0x00a6, .cev_name = "LD_UNIT_UOP" },
		{ .cev_selector = 0x00a7, .cev_name = "ST_UNIT_UOP" },
		{ .cev_selector = 0x00a8, .cev_name = "L1D_CACHE_WRITEBACK" },
		{ .cev_selector = 0x00b1, .cev_name = "LDST_X64_UOP" },
		{ .cev_selector = 0x00b2, .cev_name = "LDST_XPG_UOP" },
		{ .cev_selector = 0x00b3, .cev_name = "ATOMIC_OR_EXCLUSIVE_SUCC" },
		{ .cev_selector = 0x00b4, .cev_name = "ATOMIC_OR_EXCLUSIVE_FAIL" },
		{ .cev_selector = 0x00bf, .cev_name = "L1D_CACHE_MISS_LD_NONSPEC" },
		{ .cev_selector = 0x00c0, .cev_name = "L1D_CACHE_MISS_ST_NONSPEC" },
		{ .cev_selector = 0x00c1, .cev_name = "L1D_TLB_MISS_NONSPEC" },
		{ .cev_selector = 0x00c4, .cev_name = "ST_MEMORY_ORDER_VIOLATION_NONSPEC" },
		{ .cev_selector = 0x00c5, .cev_name = "BRANCH_COND_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c6, .cev_name = "BRANCH_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c8, .cev_name = "BRANCH_RET_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00ca, .cev_name = "BRANCH_CALL_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00cb, .cev_name = "BRANCH_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00d4, .cev_name = "L1I_TLB_MISS_DEMAND" },
		{ .cev_selector = 0x00d6, .cev_name = "MAP_DISPATCH_BUBBLE" },
		{ .cev_selector = 0x00db, .cev_name = "L1I_CACHE_MISS_DEMAND" },
		{ .cev_selector = 0x00de, .cev_name = "FETCH_RESTART" },
		{ .cev_selector = 0x00e5, .cev_name = "ST_NT_UOP" },
		{ .cev_selector = 0x00e6, .cev_name = "LD_NT_UOP" },
	},
#elif ARM64_BOARD_CONFIG_T8103
	.cel_event_count = 60,
	.cel_events = {
		{ .cev_selector = 0x0000, .cev_name = "NONE" },
		{ .cev_selector = 0x0001, .cev_name = "RETIRE_UOP" },
		{ .cev_selector = 0x0002, .cev_name = "CORE_ACTIVE_CYCLE" },
		{ .cev_selector = 0x0004, .cev_name = "L1I_TLB_FILL" },
		{ .cev_selector = 0x0005, .cev_name = "L1D_TLB_FILL" },
		{ .cev_selector = 0x0007, .cev_name = "MMU_TABLE_WALK_INSTRUCTION" },
		{ .cev_selector = 0x0008, .cev_name = "MMU_TABLE_WALK_DATA" },
		{ .cev_selector = 0x000a, .cev_name = "L2_TLB_MISS_INSTRUCTION" },
		{ .cev_selector = 0x000b, .cev_name = "L2_TLB_MISS_DATA" },
		{ .cev_selector = 0x000d, .cev_name = "MMU_VIRTUAL_MEMORY_FAULT_NONSPEC" },
		{ .cev_selector = 0x0052, .cev_name = "SCHEDULE_UOP" },
		{ .cev_selector = 0x006c, .cev_name = "INTERRUPT_PENDING" },
		{ .cev_selector = 0x0070, .cev_name = "MAP_STALL_DISPATCH" },
		{ .cev_selector = 0x0075, .cev_name = "MAP_REWIND" },
		{ .cev_selector = 0x0076, .cev_name = "MAP_STALL" },
		{ .cev_selector = 0x007c, .cev_name = "MAP_INT_UOP" },
		{ .cev_selector = 0x007d, .cev_name = "MAP_LDST_UOP" },
		{ .cev_selector = 0x007e, .cev_name = "MAP_SIMD_UOP" },
		{ .cev_selector = 0x0084, .cev_name = "FLUSH_RESTART_OTHER_NONSPEC" },
		{ .cev_selector = 0x008c, .cev_name = "INST_ALL" },
		{ .cev_selector = 0x008d, .cev_name = "INST_BRANCH" },
		{ .cev_selector = 0x008e, .cev_name = "INST_BRANCH_CALL" },
		{ .cev_selector = 0x008f, .cev_name = "INST_BRANCH_RET" },
		{ .cev_selector = 0x0090, .cev_name = "INST_BRANCH_TAKEN" },
		{ .cev_selector = 0x0093, .cev_name = "INST_BRANCH_INDIR" },
		{ .cev_selector = 0x0094, .cev_name = "INST_BRANCH_COND" },
		{ .cev_selector = 0x0095, .cev_name = "INST_INT_LD" },
		{ .cev_selector = 0x0096, .cev_name = "INST_INT_ST" },
		{ .cev_selector = 0x0097, .cev_name = "INST_INT_ALU" },
		{ .cev_selector = 0x0098, .cev_name = "INST_SIMD_LD" },
		{ .cev_selector = 0x0099, .cev_name = "INST_SIMD_ST" },
		{ .cev_selector = 0x009a, .cev_name = "INST_SIMD_ALU" },
		{ .cev_selector = 0x009b, .cev_name = "INST_LDST" },
		{ .cev_selector = 0x009c, .cev_name = "INST_BARRIER" },
		{ .cev_selector = 0x00a0, .cev_name = "L1D_TLB_ACCESS" },
		{ .cev_selector = 0x00a1, .cev_name = "L1D_TLB_MISS" },
		{ .cev_selector = 0x00a2, .cev_name = "L1D_CACHE_MISS_ST" },
		{ .cev_selector = 0x00a3, .cev_name = "L1D_CACHE_MISS_LD" },
		{ .cev_selector = 0x00a6, .cev_name = "LD_UNIT_UOP" },
		{ .cev_selector = 0x00a7, .cev_name = "ST_UNIT_UOP" },
		{ .cev_selector = 0x00a8, .cev_name = "L1D_CACHE_WRITEBACK" },
		{ .cev_selector = 0x00b1, .cev_name = "LDST_X64_UOP" },
		{ .cev_selector = 0x00b2, .cev_name = "LDST_XPG_UOP" },
		{ .cev_selector = 0x00b3, .cev_name = "ATOMIC_OR_EXCLUSIVE_SUCC" },
		{ .cev_selector = 0x00b4, .cev_name = "ATOMIC_OR_EXCLUSIVE_FAIL" },
		{ .cev_selector = 0x00bf, .cev_name = "L1D_CACHE_MISS_LD_NONSPEC" },
		{ .cev_selector = 0x00c0, .cev_name = "L1D_CACHE_MISS_ST_NONSPEC" },
		{ .cev_selector = 0x00c1, .cev_name = "L1D_TLB_MISS_NONSPEC" },
		{ .cev_selector = 0x00c4, .cev_name = "ST_MEMORY_ORDER_VIOLATION_NONSPEC" },
		{ .cev_selector = 0x00c5, .cev_name = "BRANCH_COND_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c6, .cev_name = "BRANCH_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c8, .cev_name = "BRANCH_RET_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00ca, .cev_name = "BRANCH_CALL_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00cb, .cev_name = "BRANCH_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00d4, .cev_name = "L1I_TLB_MISS_DEMAND" },
		{ .cev_selector = 0x00d6, .cev_name = "MAP_DISPATCH_BUBBLE" },
		{ .cev_selector = 0x00db, .cev_name = "L1I_CACHE_MISS_DEMAND" },
		{ .cev_selector = 0x00de, .cev_name = "FETCH_RESTART" },
		{ .cev_selector = 0x00e5, .cev_name = "ST_NT_UOP" },
		{ .cev_selector = 0x00e6, .cev_name = "LD_NT_UOP" },
	},
#elif ARM64_BOARD_CONFIG_T8112
	.cel_event_count = 59,
	.cel_events = {
		{ .cev_selector = 0x0000, .cev_name = "NONE" },
		{ .cev_selector = 0x0001, .cev_name = "RETIRE_UOP" },
		{ .cev_selector = 0x0002, .cev_name = "CORE_ACTIVE_CYCLE" },
		{ .cev_selector = 0x0004, .cev_name = "L1I_TLB_FILL" },
		{ .cev_selector = 0x0005, .cev_name = "L1D_TLB_FILL" },
		{ .cev_selector = 0x0007, .cev_name = "MMU_TABLE_WALK_INSTRUCTION" },
		{ .cev_selector = 0x0008, .cev_name = "MMU_TABLE_WALK_DATA" },
		{ .cev_selector = 0x000a, .cev_name = "L2_TLB_MISS_INSTRUCTION" },
		{ .cev_selector = 0x000b, .cev_name = "L2_TLB_MISS_DATA" },
		{ .cev_selector = 0x000d, .cev_name = "MMU_VIRTUAL_MEMORY_FAULT_NONSPEC" },
		{ .cev_selector = 0x006c, .cev_name = "INTERRUPT_PENDING" },
		{ .cev_selector = 0x0070, .cev_name = "MAP_STALL_DISPATCH" },
		{ .cev_selector = 0x0075, .cev_name = "MAP_REWIND" },
		{ .cev_selector = 0x0076, .cev_name = "MAP_STALL" },
		{ .cev_selector = 0x007c, .cev_name = "MAP_INT_UOP" },
		{ .cev_selector = 0x007d, .cev_name = "MAP_LDST_UOP" },
		{ .cev_selector = 0x007e, .cev_name = "MAP_SIMD_UOP" },
		{ .cev_selector = 0x0084, .cev_name = "FLUSH_RESTART_OTHER_NONSPEC" },
		{ .cev_selector = 0x008c, .cev_name = "INST_ALL" },
		{ .cev_selector = 0x008d, .cev_name = "INST_BRANCH" },
		{ .cev_selector = 0x008e, .cev_name = "INST_BRANCH_CALL" },
		{ .cev_selector = 0x008f, .cev_name = "INST_BRANCH_RET" },
		{ .cev_selector = 0x0090, .cev_name = "INST_BRANCH_TAKEN" },
		{ .cev_selector = 0x0093, .cev_name = "INST_BRANCH_INDIR" },
		{ .cev_selector = 0x0094, .cev_name = "INST_BRANCH_COND" },
		{ .cev_selector = 0x0095, .cev_name = "INST_INT_LD" },
		{ .cev_selector = 0x0096, .cev_name = "INST_INT_ST" },
		{ .cev_selector = 0x0097, .cev_name = "INST_INT_ALU" },
		{ .cev_selector = 0x0098, .cev_name = "INST_SIMD_LD" },
		{ .cev_selector = 0x0099, .cev_name = "INST_SIMD_ST" },
		{ .cev_selector = 0x009a, .cev_name = "INST_SIMD_ALU" },
		{ .cev_selector = 0x009b, .cev_name = "INST_LDST" },
		{ .cev_selector = 0x009c, .cev_name = "INST_BARRIER" },
		{ .cev_selector = 0x00a0, .cev_name = "L1D_TLB_ACCESS" },
		{ .cev_selector = 0x00a1, .cev_name = "L1D_TLB_MISS" },
		{ .cev_selector = 0x00a2, .cev_name = "L1D_CACHE_MISS_ST" },
		{ .cev_selector = 0x00a3, .cev_name = "L1D_CACHE_MISS_LD" },
		{ .cev_selector = 0x00a6, .cev_name = "LD_UNIT_UOP" },
		{ .cev_selector = 0x00a7, .cev_name = "ST_UNIT_UOP" },
		{ .cev_selector = 0x00a8, .cev_name = "L1D_CACHE_WRITEBACK" },
		{ .cev_selector = 0x00b1, .cev_name = "LDST_X64_UOP" },
		{ .cev_selector = 0x00b2, .cev_name = "LDST_XPG_UOP" },
		{ .cev_selector = 0x00b3, .cev_name = "ATOMIC_OR_EXCLUSIVE_SUCC" },
		{ .cev_selector = 0x00b4, .cev_name = "ATOMIC_OR_EXCLUSIVE_FAIL" },
		{ .cev_selector = 0x00bf, .cev_name = "L1D_CACHE_MISS_LD_NONSPEC" },
		{ .cev_selector = 0x00c0, .cev_name = "L1D_CACHE_MISS_ST_NONSPEC" },
		{ .cev_selector = 0x00c1, .cev_name = "L1D_TLB_MISS_NONSPEC" },
		{ .cev_selector = 0x00c4, .cev_name = "ST_MEMORY_ORDER_VIOLATION_NONSPEC" },
		{ .cev_selector = 0x00c5, .cev_name = "BRANCH_COND_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c6, .cev_name = "BRANCH_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00c8, .cev_name = "BRANCH_RET_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00ca, .cev_name = "BRANCH_CALL_INDIR_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00cb, .cev_name = "BRANCH_MISPRED_NONSPEC" },
		{ .cev_selector = 0x00d4, .cev_name = "L1I_TLB_MISS_DEMAND" },
		{ .cev_selector = 0x00d6, .cev_name = "MAP_DISPATCH_BUBBLE" },
		{ .cev_selector = 0x00db, .cev_name = "L1I_CACHE_MISS_DEMAND" },
		{ .cev_selector = 0x00de, .cev_name = "FETCH_RESTART" },
		{ .cev_selector = 0x00e5, .cev_name = "ST_NT_UOP" },
		{ .cev_selector = 0x00e6, .cev_name = "LD_NT_UOP" },
	},
#else
	.cel_event_count = 0,
	.cel_events = {},
#endif
};
