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
#define KSANCOV_IOC_TRACE            _IOW('K', 1, size_t) /* number of pcs */
#define KSANCOV_IOC_COUNTERS         _IO('K', 2)
#define KSANCOV_IOC_STKSIZE          _IOW('K', 3, size_t) /* number of pcs */

/* Establish a shared mapping of the coverage buffer. */
#define KSANCOV_IOC_MAP              _IOWR('K', 8, struct ksancov_buf_desc)

/* Establish a shared mapping of the edge address buffer. */
#define KSANCOV_IOC_MAP_EDGEMAP      _IOWR('K', 9, struct ksancov_buf_desc)

/* Log the current thread */
#define KSANCOV_IOC_START            _IOW('K', 10, uintptr_t)
#define KSANCOV_IOC_NEDGES           _IOR('K', 50, size_t)
#define KSANCOV_IOC_TESTPANIC        _IOW('K', 20, uint64_t)

/* Operations related to on-demand instrumentation */
#define KSANCOV_IOC_ON_DEMAND        _IOWR('K', 60, struct ksancov_on_demand_msg)

/* Set comparison log mode */
#define KSANCOV_IOC_CMPS_TRACE       _IOW('K', 70, size_t) /* number of cmps */
#define KSANCOV_IOC_CMPS_TRACE_FUNC  _IOW('K', 71, size_t) /* number of cmps */

/* Establish a shared mapping of the comparisons buffer. */
#define KSANCOV_IOC_CMPS_MAP         _IOWR('K', 90, struct ksancov_buf_desc)

/* Testcases buffer */
#define KSANCOV_IOC_TESTCASES       _IOW('K', 100, size_t) /* number of testcases */
#define KSANCOV_IOC_TESTCASES_MAP   _IOWR('K', 101, struct ksancov_buf_desc)
#define KSANCOV_IOC_TESTCASES_LOG   _IO('K', 102)


/*
 * ioctl
 */

struct ksancov_buf_desc {
	uintptr_t ptr;  /* ptr to shared buffer [out] */
	size_t sz;      /* size of shared buffer [out] */
};

/*
 * On-demand related functionalities
 */
typedef enum {
	KS_OD_GET_GATE = 1,
	KS_OD_SET_GATE = 2,
	KS_OD_GET_RANGE = 3,
	KS_OD_GET_BUNDLE = 4,
} ksancov_on_demand_operation_t;

struct ksancov_on_demand_msg {
	char bundle[/*KMOD_MAX_NAME*/ 64];
	ksancov_on_demand_operation_t operation;
	union {
		uint64_t gate;
		struct {
			uint32_t start;
			uint32_t stop;
		} range;
		uint64_t pc;
	};
};

/*
 * shared kernel-user mapping
 */

#define KSANCOV_MAX_EDGES         (1 << 24)
#define KSANCOV_MAX_HITS          UINT8_MAX
#define KSANCOV_TRACE_MAGIC       (uint32_t)0x5AD17F5BU
#define KSANCOV_COUNTERS_MAGIC    (uint32_t)0x5AD27F6BU
#define KSANCOV_EDGEMAP_MAGIC     (uint32_t)0x5AD37F7BU
#define KSANCOV_STKSIZE_MAGIC     (uint32_t)0x5AD47F8BU
#define KSANCOV_CMPS_TRACE_MAGIC  (uint32_t)0x5AD47F9BU

__BEGIN_DECLS

void ksancov_init(void); /* invoked by kcov_init */
int ksancov_init_dev(void);

void kcov_ksancov_init_thread(ksancov_dev_t *);
void kcov_ksancov_trace_guard(uint32_t *, void *);
void kcov_ksancov_trace_pc(kcov_thread_data_t *, uint32_t *, void*, uintptr_t);
void kcov_ksancov_trace_pc_guard_init(uint32_t *, uint32_t *);
void kcov_ksancov_pcs_init(uintptr_t *, uintptr_t *);
void kcov_ksancov_trace_cmp(kcov_thread_data_t *, uint32_t, uint64_t, uint64_t, void*);
void kcov_ksancov_trace_cmp_func(kcov_thread_data_t *, uint32_t, const void*, size_t, const void*, size_t, void*, bool);
bool kcov_ksancov_must_instrument(uintptr_t);
int ksancov_can_print_serial(void);
int ksancov_serial_print(const char *fmt, ...);
void ksancov_on_panic_log(void);

__END_DECLS


#else

#define kcov_ksancov_init_thread(dev)
#define kcov_ksancov_trace_guard(guardp, caller)
#define kcov_ksancov_trace_pc(dev, guardp, caller, sp)
#define kcov_ksancov_trace_pc_guard_init(start, stop)
#define kcov_ksancov_pcs_init(start, stop)
#define kcov_ksancov_trace_cmp(data, type, arg1, arg2, caller)
#define kcov_ksancov_trace_cmp_func(data, type, arg1, arg2, size, caller, always_log)
#define kcov_ksancov_must_instrument(addr)
#define ksancov_can_print_serial() 0
#define ksancov_serial_print(...)
#define ksancov_on_panic_log()

#endif /* CONFIG_KSANCOV */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_KSANCOV_H_ */
