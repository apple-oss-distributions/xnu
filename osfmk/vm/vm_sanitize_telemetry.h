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

#ifndef _VM_SANITIZE_TELEMETRY_H_
#define _VM_SANITIZE_TELEMETRY_H_

#include <stdint.h>
#include <sys/kdebug_triage.h>

#pragma mark Methods

/*
 * When adopting telemetry in a new method, add an enum for it here, at the
 * bottom
 */
__enum_closed_decl(vm_sanitize_method_t, uint64_t, {
	VM_SANITIZE_METHOD_MACH_MAKE_MEMORY_ENTRY = 1,
	VM_SANITIZE_METHOD_MACH_MEMORY_ENTRY_PAGE_OP,
	VM_SANITIZE_METHOD_MACH_MEMORY_ENTRY_RANGE_OP,
	VM_SANITIZE_METHOD_MACH_MEMORY_ENTRY_MAP_SIZE,
	VM_SANITIZE_METHOD_MACH_MEMORY_OBJECT_MEMORY_ENTRY,
	VM_SANITIZE_METHOD_VM_ALLOCATE_FIXED,
	VM_SANITIZE_METHOD_VM_ALLOCATE_ANYWHERE,
	VM_SANITIZE_METHOD_VM_DEALLOCATE,
	VM_SANITIZE_METHOD_MUNMAP,
	VM_SANITIZE_METHOD_VM_MAP_REMAP,
	VM_SANITIZE_METHOD_MMAP,
	VM_SANITIZE_METHOD_MAP_WITH_LINKING_NP,
	VM_SANITIZE_METHOD_ENTER_MEM_OBJ,
	VM_SANITIZE_METHOD_ENTER_MEM_OBJ_CTL,
	VM_SANITIZE_METHOD_MREMAP_ENCRYPTED,
	VM_SANITIZE_METHOD_VM_WIRE_USER,
	VM_SANITIZE_METHOD_VM_UNWIRE_USER,
	VM_SANITIZE_METHOD_VM_MAP_WIRE,
	VM_SANITIZE_METHOD_VM_MAP_UNWIRE,
	VM_SANITIZE_METHOD_VSLOCK,
	VM_SANITIZE_METHOD_VSUNLOCK,
	VM_SANITIZE_METHOD_VM_MAP_COPY_OVERWRITE,
	VM_SANITIZE_METHOD_VM_MAP_COPYIN,
	VM_SANITIZE_METHOD_VM_MAP_READ_USER,
	VM_SANITIZE_METHOD_VM_MAP_WRITE_USER,
	VM_SANITIZE_METHOD_MACH_VM_INHERIT,
	VM_SANITIZE_METHOD_VM_INHERIT,
	VM_SANITIZE_METHOD_VM32_INHERIT,
	VM_SANITIZE_METHOD_VM_MAP_INHERIT,
	VM_SANITIZE_METHOD_MINHERIT,
	VM_SANITIZE_METHOD_MACH_VM_PROTECT,
	VM_SANITIZE_METHOD_VM_PROTECT,
	VM_SANITIZE_METHOD_VM32_PROTECT,
	VM_SANITIZE_METHOD_VM_MAP_PROTECT,
	VM_SANITIZE_METHOD_MPROTECT,
	VM_SANITIZE_METHOD_USERACC,
	VM_SANITIZE_METHOD_VM_MAP_MSYNC,
	VM_SANITIZE_METHOD_MSYNC,
	VM_SANITIZE_METHOD_VM_MAP_MACHINE_ATTRIBUTE,
	VM_SANITIZE_METHOD_MINCORE,
	VM_SANITIZE_METHOD_VM_MAP_PAGE_RANGE_INFO,
	VM_SANITIZE_METHOD_VM_MAP_PAGE_RANGE_QUERY,
	VM_SANITIZE_METHOD_TEST,
});

#pragma mark Checkers

/*
 * When adopting telemetry in a new checker, add an enum for it here, at the
 * bottom (but before the "counts")
 */
__enum_closed_decl(vm_sanitize_checker_t, uint64_t, {
	VM_SANITIZE_CHECKER_ADDR_SIZE = 1,  /* arg1=addr, arg2=size, arg3=pgmask */
	VM_SANITIZE_CHECKER_PROT_CUR_MAX,   /* arg1=cur_prot, arg2=max_prot, arg3=extra_mask */
});


__enum_closed_decl(vm_sanitize_checker_count_t, uint64_t, {
	VM_SANITIZE_CHECKER_COUNT_1 = 1,
	VM_SANITIZE_CHECKER_COUNT_2,
	VM_SANITIZE_CHECKER_COUNT_3,
	VM_SANITIZE_CHECKER_COUNT_4,
	VM_SANITIZE_CHECKER_COUNT_5,
});

#pragma mark Telemetry API

/*!
 * @function vm_sanitize_send_telemetry
 * @abstract Send telemetry using CoreAnalytics when a VM API function returns
 * a return code affected by the VM API Hygiene work.
 * @param method An instance of the method enums above, indicating which VM
 * API method is returning the error.
 * @param checker An instance of the checker enums above, indicating which VM
 * checker/sanitizer caused the error.
 * @param checker_count An instance of the checker count enums above. Used to
 * distinguish in cases where the same checker can be called multiple times by
 * the same function.
 * @param ktriage_code The enum to be used for ktriage. Pass 0 to skip ktriage.
 * @param arg1 First argument. Interpretation depends on checker.
 * @param arg2 Second argument. Interpretation depends on checker.
 * @param arg3 Third argument. Interpretation depends on checker.
 * @param arg4 Fourth argument. Interpretation depends on checker.
 * @param future_ret The error code that will be returned long term when this
 * checker fails with this method.
 * @param past_ret The error code that would have been returned in the same
 * circumstances before the VM API Hygiene work.
 *
 * @note There is no \p current_ret argument, and what the method is returning
 * today should be passed as \p future_ret or \p past_ret as appropriate.
 */
void vm_sanitize_send_telemetry(
	vm_sanitize_method_t                method,
	vm_sanitize_checker_t               checker,
	vm_sanitize_checker_count_t         checker_count,
	enum vm_sanitize_subsys_error_codes ktriage_code,
	uint64_t                            arg1,
	uint64_t                            arg2,
	uint64_t                            arg3,
	uint64_t                            arg4,
	uint64_t                            future_ret,
	uint64_t                            past_ret);

#endif /* _VM_SANITIZE_TELEMETRY_H_ */
