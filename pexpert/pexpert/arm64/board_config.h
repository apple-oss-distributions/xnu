/*
 * Copyright (c) 2007-2025 Apple Inc. All rights reserved.
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 */
#ifndef _PEXPERT_ARM_BOARD_CONFIG_H
#define _PEXPERT_ARM_BOARD_CONFIG_H

#ifdef XNU_KERNEL_PRIVATE
/**
 * The board_config headers are exported and included in other projects (e.g.,
 * SPTM) which might be getting built differently (like not including standard
 * headers) which can make it difficult to include other XNU headers. In the
 * cases where this file needs to include other headers to set its defines, as
 * long as those defines aren't used outside of XNU, it's best to just wrap them
 * in XNU_KERNEL_PRIVATE to prevent any build issues in dependent projects.
 */
#include <mach/machine.h>
#endif /* XNU_KERNEL_PRIVATE */

#if !defined(KERNEL_PRIVATE) && !defined(SPTM_TESTING_PRIVATE)
/**
 * This file (and other board_config adjacent files) are only exported into the
 * internal userspace SDK exclusively for usage by the SPTM userspace testing
 * system. Let's enforce this by error'ing the build if an SPTM-specific define
 * is not set. If your userspace project is not the SPTM testing system, then do
 * not use these files!
 *
 * This check does not apply to the kernel itself, or when this file is exported
 * into Kernel.framework.
 */
#error This file is only included in the userspace internal SDK for the SPTM project
#endif /* !defined(KERNEL_PRIVATE) && !defined(SPTM_TESTING_PRIVATE) */

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
#define MAX_CPUS                       20
#define MAX_CPU_CLUSTERS               6
#define MAX_CPU_CLUSTER_PHY_ID         10
#define HAS_IOA                        1

#ifndef CONFIG_SPTM
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define XNU_MONITOR                    1 /* Secure pmap runtime */
#endif /* !CONFIG_SPTM */


#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1


#define SPTM_TRACING_DISABLED          1

#if DEVELOPMENT || DEBUG
#define XNU_ENABLE_PROCESSOR_EXIT      1 /* Enable xnu processor_exit() by default */
#endif
#define XNU_LOG_MCC                    1

#define NO_XNU_PLATFORM_ERROR_HANDLER  1
#endif  /* ARM64_BOARD_CONFIG_T6000 */

#ifdef ARM64_BOARD_CONFIG_T6020
#include <pexpert/arm64/H14.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       24
#define MAX_CPU_CLUSTERS               6
#define MAX_CPU_CLUSTER_PHY_ID         10
#define HAS_IOA                        1


#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define XNU_CLUSTER_POWER_DOWN         1 /* Enable xnu cluster power down by default */
#define RHODES_CLUSTER_POWERDOWN_WORKAROUND 1 /* Workaround for rdar://89107373 (Rhodes cluster power down: cannot manually power down and up a core multiple times without powering down the cluster) */
#define XNU_PLATFORM_ERROR_HANDLER     1 /* This platform uses the platform error handler inside XNU rather than a kext */
#ifdef __BUILDING_XNU_LIBRARY__
/*
 * TODO <rdar://159734763> will make it possible to run unit tests on different
 * targets.
 * T6020 is not an ECC capable platform, but we define it as such to allow ECC
 * unit tests to compile and run.
 */
#define XNU_HANDLE_ECC                 1
#endif /* __BUILDING_XNU_LIBRARY__ */
#define XNU_LOG_MCC                    1
#define EXTENDED_USER_VA_SUPPORT       1 /* On certain OSes, support larger user address spaces */
#endif  /* ARM64_BOARD_CONFIG_T6020 */








#ifdef ARM64_BOARD_CONFIG_T8101
#include <pexpert/arm64/H13.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#ifndef CONFIG_SPTM
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define XNU_MONITOR                    1 /* Secure pmap runtime */
#endif /* !CONFIG_SPTM */


#define USE_APPLEARMSMP                1


#define NO_XNU_PLATFORM_ERROR_HANDLER  1
#endif  /* ARM64_BOARD_CONFIG_T8101 */

#ifdef ARM64_BOARD_CONFIG_T8103
#include <pexpert/arm64/H13.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2

#ifndef CONFIG_SPTM
#define PMAP_CS                        1
#define PMAP_CS_ENABLE                 1
#define XNU_MONITOR                    1 /* Secure pmap runtime */
#endif /* !CONFIG_SPTM */


#define USE_APPLEARMSMP                1


#define SPTM_TRACING_DISABLED          1

#define NO_XNU_PLATFORM_ERROR_HANDLER  1
#endif  /* ARM64_BOARD_CONFIG_T8103 */


#ifdef ARM64_BOARD_CONFIG_T8112
#include <pexpert/arm64/H14.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8 /* Actually has 6 CPUs, see doc/building/xnu_build_consolidation.md for more info */
#define MAX_CPU_CLUSTERS               2

#define USE_APPLEARMSMP                1

#define NO_XNU_PLATFORM_ERROR_HANDLER  1
#endif  /* ARM64_BOARD_CONFIG_T8112 */


#ifdef ARM64_BOARD_CONFIG_T8122_T8130
#include <pexpert/arm64/H15.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       8
#define MAX_CPU_CLUSTERS               2
#define HAS_IOA                        1


#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define XNU_PLATFORM_ERROR_HANDLER     1 /* This platform uses the platform error handler inside XNU rather than a kext */
#define XNU_LOG_MCC                    1

#endif  /* ARM64_BOARD_CONFIG_T8122_T8130 */

#ifdef ARM64_BOARD_CONFIG_T8132
#include <pexpert/arm64/H16.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       10
#define MAX_CPU_CLUSTERS               2

#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define XNU_PLATFORM_ERROR_HANDLER     1 /* This platform uses the platform error handler inside XNU rather than a kext */
#define XNU_LOG_MCC                    1
#define NO_CPU_OVRD                    1 /* CPU_OVRD register accesses are banned */



#endif  /* ARM64_BOARD_CONFIG_T8132 */


#ifdef ARM64_BOARD_CONFIG_T8142
#include <pexpert/arm64/H17.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       10
#define MAX_CPU_CLUSTERS               2

#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define NO_CPU_OVRD                    1 /* CPU_OVRD register accesses are banned */


#define XNU_LOG_MCC                    1

#define XNU_PLATFORM_ERROR_HANDLER     1 /* This platform uses the platform error handler inside XNU rather than a kext */

#define HAS_PRIVATE_L2_CACHE           1 /* Has Private L2 cache */
#endif  /* ARM64_BOARD_CONFIG_T8142 */






#ifdef ARM64_BOARD_CONFIG_T6030

#include <pexpert/arm64/H15.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       12
#define MAX_CPU_CLUSTERS               2
#define HAS_IOA                        1

#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define XNU_PLATFORM_ERROR_HANDLER     1 /* This platform uses the platform error handler inside XNU rather than a kext */
#define XNU_LOG_MCC                    1
#endif  /* ARM64_BOARD_CONFIG_T6030 */


#ifdef ARM64_BOARD_CONFIG_T6031

#include <pexpert/arm64/H15.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       32
#define MAX_CPU_CLUSTERS               6
#define MAX_CPU_CLUSTER_PHY_ID         10
#define HAS_IOA                        1

#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define XNU_CLUSTER_POWER_DOWN         1 /* Enable xnu cluster power down by default */
#define RHODES_CLUSTER_POWERDOWN_WORKAROUND 1 /* Workaround for rdar://89107373 (Rhodes cluster power down: cannot manually power down and up a core multiple times without powering down the cluster) */
#endif  /* ARM64_BOARD_CONFIG_T6031 */

#ifdef ARM64_BOARD_CONFIG_T6041
#include <pexpert/arm64/H16.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       16
#define MAX_CPU_CLUSTERS               3

#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define NO_CPU_OVRD                    1 /* CPU_OVRD register accesses are banned */
#define XNU_SUPPORT_BOOTCPU_SHUTDOWN   1
#define RHODES_CLUSTER_POWERDOWN_WORKAROUND 1 /* Workaround for rdar://89107373 (Rhodes cluster power down: cannot manually power down and up a core multiple times without powering down the cluster) */


#endif  /* ARM64_BOARD_CONFIG_T6041 */

#ifdef ARM64_BOARD_CONFIG_T6050
/**
 * This needs to be set before including H17.h so that the definitions in
 * apple_arm64_cpu.h are interpreted correctly.
 */
#define HAS_MCORE                      1
#include <pexpert/arm64/H17.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       36
#define MAX_CPU_CLUSTERS               6
#define MAX_CPU_CLUSTER_PHY_ID         18

#define __ARM_42BIT_PA_SPACE__         1
#define USE_APPLEARMSMP                1
#define NO_CPU_OVRD                    1 /* CPU_OVRD register accesses are banned */
#define XNU_SUPPORT_BOOTCPU_SHUTDOWN   1
#define RHODES_CLUSTER_POWERDOWN_WORKAROUND 1 /* Workaround for rdar://89107373 (Rhodes cluster power down: cannot manually power down and up a core multiple times without powering down the cluster) */



#endif  /* ARM64_BOARD_CONFIG_T6050 */





#ifdef ARM64_BOARD_CONFIG_VMAPPLE
#include <pexpert/arm64/VMAPPLE.h>

#define MAX_L2_CLINE                   7
#define MAX_CPUS                       32 /* limited by CPU copy window size and cpu checkin mask */
#define MAX_CPU_CLUSTERS               1

#define USE_APPLEARMSMP                1

#define NO_XNU_PLATFORM_ERROR_HANDLER  1


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

#if defined(XNU_KERNEL_PRIVATE) && defined(PREFER_ARM64_32_BINARIES)
#define PREFERRED_USER_CPU_TYPE CPU_TYPE_ARM64_32
#define PREFERRED_USER_CPU_SUBTYPE CPU_SUBTYPE_ARM64_32_V8
#endif /* defined(XNU_KERNEL_PRIVATE) && defined(PREFER_ARM64_32_BINARIES) */


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




#if CONFIG_SPTM && (DEBUG || DEVELOPMENT)
#define HAS_SPTM_SYSCTL 1
#endif /* CONFIG_SPTM && (DEBUG || DEVELOPMENT) */



#endif /* ! _PEXPERT_ARM_BOARD_CONFIG_H */
