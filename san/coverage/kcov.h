/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _KCOV_H_
#define _KCOV_H_

#if KERNEL_PRIVATE

#if !CONFIG_KCOV && __has_feature(coverage_sanitizer)
# error "Coverage sanitizer enabled in compiler, but kernel is not configured for KCOV"
#endif

#if CONFIG_KCOV

/* Forward declaration for types used in interfaces below. */
typedef struct kcov_cpu_data kcov_cpu_data_t;
typedef struct kcov_thread_data kcov_thread_data_t;


__BEGIN_DECLS

/* osfmk exported */
kcov_cpu_data_t *current_kcov_data(void);
kcov_cpu_data_t *cpu_kcov_data(int);

/* Init code */
void kcov_init_thread(kcov_thread_data_t *);
void kcov_start_cpu(int cpuid);

/* helpers */
void kcov_panic_disable(void);

/* per-thread */
struct kcov_thread_data *kcov_get_thread_data(thread_t);

void kcov_enable(void);
void kcov_disable(void);

/*
 * SanitizerCoverage ABI
 */
void __sanitizer_cov_pcs_init(uintptr_t *start, uintptr_t *stop);
void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
void __sanitizer_cov_trace_pc_indirect(void *callee);
void __sanitizer_cov_trace_pc(void);

__END_DECLS

#endif /* CONFIG_KCOV */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_H_ */
