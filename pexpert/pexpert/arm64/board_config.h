/*
 * Copyright (c) 2007-2023 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#include <mach/machine.h>

/*
 * Per-SoC configuration.  General order is:
 *
 * CPU type
 * CPU configuration
 * CPU feature disables / workarounds
 * CPU topology
 * Other platform configuration (e.g. DARTs, PPL)
 *
 * This should answer the question: "what's unique about this SoC?"
 *
 * arm64/H*.h should answer the question: "what's unique about this CPU core?"
 *
 * For __ARM_AMP__ systems that have different cache line sizes on different
 * clusters, MAX_L2_CLINE must reflect the largest L2 cache line size
 * across all clusters.
 */

#ifdef ARM64_BOARD_CONFIG_T6000
#include <pexpert/arm64/H13.h>


#define MAX_L2_CLINE                   7
#define MAX_CPUS                       10
#define MAX_CPU_CLUSTERS               3
#define MAX_CPU_CLUSTER_PHY_ID         10
#define HAS_IOA                        1

#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define XNU_MONITOR                    1 /* Secure pmap runtime */
#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#if DEVELOPMENT || DEBUG
#define XNU_ENABLE_PROCESSOR_EXIT      1 /* Enable xnu processor_exit() by default */
#endif
#define XNU_HANDLE_MCC                 1 /* This platform may support MCC error recovery */
#endif  /* ARM64_BOARD_CONFIG_T6000 */









#ifdef ARM64_BOARD_CONFIG_T8101
#include <pexpert/arm64/H13.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define XNU_MONITOR                    1 /* Secure pmap runtime */
#endif  /* ARM64_BOARD_CONFIG_T8101 */

#ifdef ARM64_BOARD_CONFIG_T8103
#include <pexpert/arm64/H13.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define XNU_MONITOR                    1 /* Secure pmap runtime */
#endif  /* ARM64_BOARD_CONFIG_T8103 */













#ifdef ARM64_BOARD_CONFIG_BCM2837
#include <pexpert/arm64/BCM2837.h>

#define MAX_L2_CLINE                   6
#define MAX_CPUS                       4
#define MAX_CPU_CLUSTERS               1

#define CORE_NCTRS                     8 /* Placeholder; KPC is not enabled for this target */
#endif  /* ARM64_BOARD_CONFIG_BCM2837 */

#ifdef ARM64_BOARD_CONFIG_VMAPPLE
#include <pexpert/arm64/VMAPPLE.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       32 /* limited by CPU copy window size and cpu checkin mask */
#define MAX_CPU_CLUSTERS               1

#define CORE_NCTRS                     2

#define USE_APPLEARMSMP                1

#if XNU_TARGET_OS_WATCH
#define PREFER_ARM64_32_BINARIES       1
#endif

#endif  /* ARM64_BOARD_CONFIG_VMAPPLE */


#ifndef HAS_UNCORE_CTRS
#undef UNCORE_VERSION
#undef UNCORE_PER_CLUSTER
#undef UNCORE_NCTRS
#endif

#if MAX_CPU_CLUSTERS == 1
#undef __ARM_AMP__
#endif

#ifndef MAX_CPU_CLUSTER_PHY_ID
#define MAX_CPU_CLUSTER_PHY_ID (MAX_CPU_CLUSTERS - 1)
#endif

#ifdef PREFER_ARM64_32_BINARIES
#define PREFERRED_USER_CPU_TYPE CPU_TYPE_ARM64_32
#define PREFERRED_USER_CPU_SUBTYPE CPU_SUBTYPE_ARM64_32_V8
#endif


/*
 * Some platforms have very expensive timebase routines.  An optimization
 * is to avoid switching timers on kernel exit/entry, which results in all
 * time billed to the system timer.  However, when exposed to userspace, it's
 * reported as user time to indicate that work was done on behalf of
 * userspace.
 */

#if CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
#define PRECISE_USER_KERNEL_TIME HAS_FAST_CNTVCT
#else /* CONFIG_SKIP_PRECISE_USER_KERNEL_TIME */
#define PRECISE_USER_KERNEL_TIME 1
#endif /* !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME */

/**
 * On supported hardware, debuggable builds make the HID bits read-only
 * without locking them.  This lets people manually modify HID bits while
 * debugging, since they can use a debugging tool to first reset the HID
 * bits back to read/write.  However it will still catch xnu changes that
 * accidentally write to HID bits after they've been made read-only.
 */

#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */
