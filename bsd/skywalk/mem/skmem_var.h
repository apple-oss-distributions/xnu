/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_MEM_SKMEMVAR_H
#define _SKYWALK_MEM_SKMEMVAR_H

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/mem/skmem_region_var.h>
#include <skywalk/mem/skmem_cache_var.h>
#include <skywalk/mem/skmem_arena_var.h>

#if defined(__arm__) || defined(__arm64__)
#define SKMEM_PAGE_SIZE PAGE_MAX_SIZE
#else /* __i386__, __x86_64__ */
#define SKMEM_PAGE_SIZE PAGE_SIZE
#endif /* __i386__, __x86_64__ */

/*
 * Initial segment sizes for non-monolithic regions.  Smaller size allows more
 * finer-grained control over the memory, at the expense of overheads.  The
 * effective region segment size is computed by skmem_region_params_config(),
 * depending on the number and size of objects.  This may be overridden by
 * the "skmem_seg_size" and "skmem_buf_seg_size" boot-arg.
 *
 * The sizes are always multiples of SKMEM_PAGE_SIZE.
 */
#define SKMEM_MIN_SEG_SIZE      (16 * 1024)
#define SKMEM_SEG_SIZE          SKMEM_MIN_SEG_SIZE /* default for all */
#define SKMEM_MD_SEG_SIZE       (16 * 1024)     /* default for metadata */
#define SKMEM_DRV_BUF_SEG_SIZE  (64 * 1024)     /* default for device buffer */
#define SKMEM_USR_BUF_SEG_SIZE  (16 * 1024)     /* default for user buffer */

#define SKMEM_DRV_BUF_SEG_MULTIPLIER    2

#define SKMEM_ARENA_PREFIX      "ska"
#define SKMEM_REGION_PREFIX     "skr"
#define SKMEM_CACHE_PREFIX      "skc"
#define SKMEM_ZONE_PREFIX       "skywalk"

extern lck_attr_t skmem_lock_attr;
extern lck_grp_t skmem_lock_grp;
extern uint32_t skmem_usr_buf_seg_size;

#if (DEVELOPMENT || DEBUG)
SYSCTL_DECL(_kern_skywalk_mem);
#endif /* (DEVELOPMENT || DEBUG) */

#define SKMEM_MEM_CONSTRAINED_DEVICE    \
    (max_mem_actual <= (2ULL * 1024ULL * 1024ULL * 1024ULL))

__BEGIN_DECLS
extern void skmem_init(void);
extern void skmem_fini(void);
extern const struct skmem_region_params *skmem_get_default(skmem_region_id_t);
extern uint32_t skmem_cpu_cache_line_size(void);
extern void skmem_dispatch(thread_call_t, void (*func)(void), uint64_t);
extern struct skmem_region *skmem_get_sysctls_region(void);
extern char *skmem_dump(struct skmem_region *);
extern boolean_t skmem_lowmem_check(void);
#if (DEVELOPMENT || DEBUG)
extern void skmem_test_init(void);
extern void skmem_test_fini(void);
extern bool skmem_test_enabled(void);
#endif /* (DEVELOPMENT || DEBUG) */
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_MEM_SKMEMVAR_H */
