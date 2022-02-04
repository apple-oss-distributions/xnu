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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifndef _KCOV_KSANCOV_H_
#define _KCOV_KSANCOV_H_

#include <stdint.h>
#include <sys/ioccom.h>
#include <san/kcov_data.h>

#if KERNEL_PRIVATE

#if CONFIG_KSANCOV


#define KSANCOV_DEVNODE "ksancov"
#define KSANCOV_PATH "/dev/" KSANCOV_DEVNODE

/* Set mode */
#define KSANCOV_IOC_TRACE        _IOW('K', 1, size_t) /* number of pcs */
#define KSANCOV_IOC_COUNTERS     _IO('K', 2)
#define KSANCOV_IOC_STKSIZE      _IOW('K', 3, size_t) /* number of pcs */

/* Establish a shared mapping of the coverage buffer. */
#define KSANCOV_IOC_MAP          _IOWR('K', 8, struct ksancov_buf_desc)

/* Establish a shared mapping of the edge address buffer. */
#define KSANCOV_IOC_MAP_EDGEMAP  _IOWR('K', 9, struct ksancov_buf_desc)

/* Log the current thread */
#define KSANCOV_IOC_START        _IOW('K', 10, uintptr_t)
#define KSANCOV_IOC_NEDGES       _IOR('K', 50, size_t)
#define KSANCOV_IOC_TESTPANIC    _IOW('K', 20, uint64_t)

/*
 * ioctl
 */

struct ksancov_buf_desc {
	uintptr_t ptr;  /* ptr to shared buffer [out] */
	size_t sz;      /* size of shared buffer [out] */
};

/*
 * shared kernel-user mapping
 */

#define KSANCOV_MAX_EDGES       512UL*1024
#define KSANCOV_MAX_HITS        UINT8_MAX
#define KSANCOV_TRACE_MAGIC     (uint32_t)0x5AD17F5BU
#define KSANCOV_COUNTERS_MAGIC  (uint32_t)0x5AD27F6BU
#define KSANCOV_EDGEMAP_MAGIC   (uint32_t)0x5AD37F7BU
#define KSANCOV_STKSIZE_MAGIC   (uint32_t)0x5AD47F8BU


__BEGIN_DECLS

int ksancov_init_dev(void);

void kcov_ksancov_init_thread(ksancov_dev_t *);
void kcov_ksancov_trace_guard(uint32_t *, void *);
void kcov_ksancov_trace_pc(kcov_thread_data_t *, uint32_t *, void*, uintptr_t);
void kcov_ksancov_trace_pc_guard_init(uint32_t *, uint32_t *);
void kcov_ksancov_pcs_init(uintptr_t *, uintptr_t *);

__END_DECLS


#else

#define kcov_ksancov_init_thread(dev)
#define kcov_ksancov_trace_guard(guardp, caller)
#define kcov_ksancov_trace_pc(dev, guardp, caller, sp)
#define kcov_ksancov_trace_pc_guard_init(start, stop)
#define kcov_ksancov_pcs_init(start, stop)

#endif /* CONFIG_KSANCOV */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_KSANCOV_H_ */
