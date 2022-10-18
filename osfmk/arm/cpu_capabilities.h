/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
#ifdef  PRIVATE

#ifndef _ARM_CPU_CAPABILITIES_H
#define _ARM_CPU_CAPABILITIES_H

#if defined (__arm__) || defined (__arm64__)

#ifndef __ASSEMBLER__
#include <stdint.h>
#include <mach/vm_types.h>
#endif


#define USER_TIMEBASE_NONE   0
#define USER_TIMEBASE_SPEC   1
#define USER_TIMEBASE_NOSPEC 2
#define USER_TIMEBASE_NOSPEC_APPLE 3

/*
 * This is the authoritative way to determine from user mode what
 * implementation-specific processor features are available.
 * This API only supported for Apple internal use.
 *
 */

/*
 * Bit definitions for _cpu_capabilities:
 */
#define kHasFeatFP16                    0x00000008      // ARM v8.2 NEON FP16 supported
#define kCache32                        0x00000010      // cache line size is 32 bytes
#define kCache64                        0x00000020      // cache line size is 64 bytes
#define kCache128                       0x00000040      // cache line size is 128 bytes
#define kFastThreadLocalStorage         0x00000080      // TLS ptr is kept in a user-mode-readable register
#define kHasAdvSIMD                     0x00000100      // Advanced SIMD is supported
#define kHasAdvSIMD_HPFPCvt             0x00000200      // Advanced SIMD half-precision
#define kHasVfp                         0x00000400      // VFP is supported
#define kHasUCNormalMemory              0x00000800      // Uncacheable normal memory type supported
#define kHasEvent                       0x00001000      // WFE/SVE and period event wakeup
#define kHasFMA                         0x00002000      // Fused multiply add is supported
#define kHasFeatFHM                     0x00004000      // Optional ARMv8.2 FMLAL/FMLSL instructions (required in ARMv8.4)
#define kUP                             0x00008000      // set if (kNumCPUs == 1)
#define kNumCPUs                        0x00FF0000      // number of CPUs (see _NumCPUs() below)
#define kHasARMv8Crypto                 0x01000000      // Optional ARMv8 Crypto extensions
#define kHasFeatLSE                     0x02000000      // ARMv8.1 Atomic instructions supported
#define kHasARMv8Crc32                  0x04000000      // Optional ARMv8 crc32 instructions (required in ARMv8.1)
#define kHasFeatSHA512                  0x80000000      // Optional ARMv8.2 SHA512 instructions
/* Extending into 64-bits from here: */
#define kHasFeatSHA3            0x0000000100000000      // Optional ARMv8.2 SHA3 instructions
#define kHasFeatFCMA            0x0000000200000000      // ARMv8.3 complex number instructions
#define kHasFEATFlagM           0x0000010000000000
#define kHasFEATFlagM2          0x0000020000000000
#define kHasFeatDotProd         0x0000040000000000
#define kHasFeatRDM             0x0000080000000000
#define kHasFeatSPECRES         0x0000100000000000
#define kHasFeatSB              0x0000200000000000
#define kHasFeatFRINTTS         0x0000400000000000
#define kHasArmv8GPI            0x0000800000000000
#define kHasFeatLRCPC           0x0001000000000000
#define kHasFeatLRCPC2          0x0002000000000000
#define kHasFeatJSCVT           0x0004000000000000
#define kHasFeatPAuth           0x0008000000000000
#define kHasFeatDPB             0x0010000000000000
#define kHasFeatDPB2            0x0020000000000000
#define kHasFeatLSE2            0x0040000000000000
#define kHasFeatCSV2            0x0080000000000000
#define kHasFeatCSV3            0x0100000000000000
#define kHasFeatDIT             0x0200000000000000
#define kHasFP_SyncExceptions   0x0400000000000000

/* Individual features coalesced to save bits */
#define kHasFeatSHA256          kHasARMv8Crypto
#define kHasFeatSHA1            kHasARMv8Crypto
#define kHasFeatAES             kHasARMv8Crypto
#define kHasFeatPMULL           kHasARMv8Crypto

/* Deprecated names */
#define kHasNeonFP16            kHasFeatFP16
#define kHasNeon                kHasAdvSIMD
#define kHasNeonHPFP            kHasAdvSIMD_HPFPCvt
#define kHasARMv82FHM           kHasFeatFHM
#define kHasARMv81Atomics       kHasFeatLSE
#define kHasARMv82SHA512        kHasFeatSHA512
#define kHasARMv82SHA3          kHasFeatSHA3
#define kHasARMv83CompNum       kHasFeatFCMA

#define kNumCPUsShift                   16              // see _NumCPUs() below
/*
 * Bit definitions for multiuser_config:
 */
#define kIsMultiUserDevice      0x80000000      // this device is in multiuser mode
#define kHasSecondaryUsers      0x40000000      // this device has Secondary Users
#define kMultiUserCurrentUserMask       0x3fffffff      // the current user UID of the multiuser device

#ifndef __ASSEMBLER__
#include <sys/commpage.h>

__BEGIN_DECLS
extern uint64_t _get_cpu_capabilities( void );
__END_DECLS

__inline static
int
_NumCPUs( void )
{
	return (_get_cpu_capabilities() & kNumCPUs) >> kNumCPUsShift;
}


typedef struct {
	volatile uint64_t       TimeBase;
	volatile uint32_t       TimeStamp_sec;
	volatile uint32_t       TimeStamp_usec;
	volatile uint32_t       TimeBaseTicks_per_sec;
	volatile uint32_t       TimeBaseTicks_per_usec;
	volatile uint64_t       TimeBase_magic;
	volatile uint32_t       TimeBase_add;
	volatile uint32_t       TimeBase_shift;
} commpage_timeofday_data_t;

__BEGIN_DECLS
extern vm_address_t                             _get_commpage_priv_address(void);
extern vm_address_t                             _get_commpage_ro_address(void);
extern vm_address_t                             _get_commpage_text_priv_address(void);
__END_DECLS

#endif /* __ASSEMBLER__ */


/*
 * The shared kernel/user "comm page(s)":
 */

#if defined(__LP64__)

#define _COMM_PAGE64_BASE_ADDRESS               (0x0000000FFFFFC000ULL) /* In TTBR0 */
#define _COMM_PAGE64_RO_ADDRESS                 (0x0000000FFFFF4000ULL) /* In TTBR0 */
#define _COMM_PAGE64_AREA_LENGTH                (_COMM_PAGE32_AREA_LENGTH)
#define _COMM_PAGE64_AREA_USED                  (-1)

#define _COMM_PAGE_PRIV(_addr_)                 ((_addr_) - (_COMM_PAGE_START_ADDRESS) + _get_commpage_priv_address())

#ifdef KERNEL_PRIVATE
#define _COMM_PAGE_RW_OFFSET                    (0)
#define _COMM_PAGE_RO_OFFSET                    (0)
#define _COMM_PAGE_AREA_LENGTH                  (PAGE_SIZE)

#define _COMM_PAGE_BASE_ADDRESS                 (_get_commpage_priv_address())
#define _COMM_PAGE_START_ADDRESS                (_get_commpage_priv_address())
#define _COMM_PAGE_RO_ADDRESS                   (_get_commpage_ro_address())

/**
 * This represents the size of the memory region that the commpage is nested in.
 * On 4K page systems, this is 1GB, and on 16KB page systems this is technically
 * only 32MB, but to keep consistency across address spaces we always reserve
 * 1GB for the commpage on ARM devices.
 *
 * The commpage itself only takes up a single page, but its page tables are
 * being shared across every user process. Entries should not be allowed to
 * be created in those shared tables, which is why the VM uses these values to
 * reserve the entire nesting region in every user process address space.
 *
 * If the commpage base address changes, these values might also need to be
 * updated.
 */
#define _COMM_PAGE64_NESTING_START                (0x0000000FC0000000ULL)
#define _COMM_PAGE64_NESTING_SIZE                 (0x40000000ULL) /* 1GiB */
_Static_assert((_COMM_PAGE64_BASE_ADDRESS >= _COMM_PAGE64_NESTING_START) &&
    (_COMM_PAGE64_BASE_ADDRESS < (_COMM_PAGE64_NESTING_START + _COMM_PAGE64_NESTING_SIZE)),
    "_COMM_PAGE64_BASE_ADDRESS is not within the nesting region. Commpage nesting "
    "region probably needs to be updated.");

#else /* KERNEL_PRIVATE */
/*
 * <sys/commpage.h> defines a couple of convenience macros
 * to help read data from the commpage.
 */
#define _COMM_PAGE_AREA_LENGTH                  (4096)

#define _COMM_PAGE_BASE_ADDRESS                 _COMM_PAGE64_BASE_ADDRESS
#define _COMM_PAGE_START_ADDRESS                _COMM_PAGE64_BASE_ADDRESS
#define _COMM_PAGE_RO_ADDRESS                   _COMM_PAGE64_RO_ADDRESS
#endif /* KERNEL_PRIVATE */

#else /* __LP64__ */

#define _COMM_PAGE64_BASE_ADDRESS               (-1)
#define _COMM_PAGE64_AREA_LENGTH                (-1)
#define _COMM_PAGE64_AREA_USED                  (-1)

// macro to change a user comm page address to one that is accessible from privileged mode
// this macro is stubbed as PAN is not available on AARCH32,
// but this may still be required for compatibility
#define _COMM_PAGE_PRIV(_addr_)                 (_addr_)

#ifdef KERNEL_PRIVATE
#define _COMM_PAGE_RW_OFFSET                    (_get_commpage_priv_address()-_COMM_PAGE_BASE_ADDRESS)
#define _COMM_PAGE_RO_OFFSET                    (_get_commpage_ro_address()-_COMM_PAGE_RO_ADDRESS)
#define _COMM_PAGE_AREA_LENGTH                  (PAGE_SIZE)
#else /* KERNEL_PRIVATE */
#define _COMM_PAGE_AREA_LENGTH                  (4096)
#endif /* KERNEL_PRIVATE */

#define _COMM_PAGE_BASE_ADDRESS                 _COMM_PAGE32_BASE_ADDRESS
#define _COMM_PAGE_START_ADDRESS                _COMM_PAGE32_BASE_ADDRESS
#define _COMM_PAGE_RO_ADDRESS                   _COMM_PAGE32_RO_ADDRESS

#endif /* __LP64__ */

#define _COMM_PAGE32_BASE_ADDRESS               (0xFFFF4000)            /* Must be outside of normal map bounds */
#define _COMM_PAGE32_RO_ADDRESS                 (0xFFFFC000)            /* Must be outside of normal map bounds */
#define _COMM_PAGE32_AREA_LENGTH                (_COMM_PAGE_AREA_LENGTH)
#define _COMM_PAGE32_TEXT_START                 (-1)

#define _COMM_PAGE32_OBJC_SIZE                  0ULL
#define _COMM_PAGE32_OBJC_BASE                  0ULL
#define _COMM_PAGE64_OBJC_SIZE                  0ULL
#define _COMM_PAGE64_OBJC_BASE                  0ULL

/*
 * Comm page layout versions
 *
 * If you need to create an RO variant of an existing commpage field (see "Comm page data fields"
 * description below), bump the maximum value of _COMM_PAGE_LAYOUT_VERSION.  The kernel should
 * always use the latest version.  Individual build targets may default to lower versions as
 * needed.  For layout versions lower than the version in which an RO variant was added, the
 * field should be defined to use the "legacy" RW offset.  In general, we expect these comm page
 * fields to only be used by platform-level binaries, which are typically coupled to the SDK.
 * A notable exception are simulator targets, which must run the latest platform binaries against
 * older host kernels.  Individual builds can also override _COMM_PAGE_LAYOUT_VERSION if they
 * should need to for some reason.
 * Note that we don't use the _COMM_PAGE_VERSION field to provide conditional runtime access
 * to these RO fields, as the version resides in the legacy kernel-writable page and could be
 * spoofed by an attacker.
 */

#ifndef _COMM_PAGE_LAYOUT_VERSION

#if KERNEL
#define _COMM_PAGE_LAYOUT_VERSION 1
#elif TARGET_OS_SIMULATOR
// Simulators require running platform libraries built against new SDKs on older hosts
#define _COMM_PAGE_LAYOUT_VERSION 0
#else
#define _COMM_PAGE_LAYOUT_VERSION 1
#endif

#endif // #ifndef _COMM_PAGE_LAYOUT_VERSION

/*
 * Comm page data fields
 *
 * There is always at least one comm page, backed by a physical page with a kernel RW mapping.
 * Apply the _COMM_PAGE_PRIV macro to use this mapping in kernel mode.
 * Depending on device configuration, there may be an additional comm page, backed by a physical
 * page with a kernel RO mapping.  This is an additional security measure for certain high-value
 * comm page fields which only need to be accessed from the kernel during early boot.
 * Fields that wish to use this page when available should be defined here as an offset from
 * _COMM_PAGE_RO_ADDRESS instead of _COMM_PAGE_START_ADDRESS, and should be placed at an offset
 * that does not overlap with any other RO or RW field.  If an existing field is migrated from
 * the RW to the RO page, the RW definition should be preserved with a _LEGACY suffix in order
 * to maintain binary compatibility.
 */
#define _COMM_PAGE_SIGNATURE                    (_COMM_PAGE_START_ADDRESS+0x000)        // first few bytes are a signature
#define _COMM_PAGE_SIGNATURELEN                 (0x10)
#define _COMM_PAGE_CPU_CAPABILITIES64           (_COMM_PAGE_START_ADDRESS+0x010)        /* uint64_t _cpu_capabilities */
#define _COMM_PAGE_UNUSED                       (_COMM_PAGE_START_ADDRESS+0x018)        /* 6 unused bytes */
#define _COMM_PAGE_VERSION                      (_COMM_PAGE_START_ADDRESS+0x01E)        // 16-bit version#
#define _COMM_PAGE_THIS_VERSION                 3                                       // version of the commarea format

#define _COMM_PAGE_CPU_CAPABILITIES             (_COMM_PAGE_START_ADDRESS+0x020)        // uint32_t _cpu_capabilities
#define _COMM_PAGE_NCPUS                        (_COMM_PAGE_START_ADDRESS+0x022)        // uint8_t number of configured CPUs

#define _COMM_PAGE_USER_PAGE_SHIFT_32_LEGACY    (_COMM_PAGE_START_ADDRESS+0x024)        // VM page shift for 32-bit processes
#if _COMM_PAGE_LAYOUT_VERSION >= 1
#define _COMM_PAGE_USER_PAGE_SHIFT_32           (_COMM_PAGE_RO_ADDRESS+0x024)           // VM page shift for 32-bit processes
#else
#define _COMM_PAGE_USER_PAGE_SHIFT_32            _COMM_PAGE_USER_PAGE_SHIFT_32_LEGACY
#endif

#define _COMM_PAGE_USER_PAGE_SHIFT_64_LEGACY    (_COMM_PAGE_START_ADDRESS+0x025)        // VM page shift for 64-bit processes
#if _COMM_PAGE_LAYOUT_VERSION >= 1
#define _COMM_PAGE_USER_PAGE_SHIFT_64           (_COMM_PAGE_RO_ADDRESS+0x025)           // VM page shift for 64-bit processes
#else
#define _COMM_PAGE_USER_PAGE_SHIFT_64            _COMM_PAGE_USER_PAGE_SHIFT_64_LEGACY
#endif

#define _COMM_PAGE_CACHE_LINESIZE               (_COMM_PAGE_START_ADDRESS+0x026)        // uint16_t cache line size
#define _COMM_PAGE_UNUSED4                      (_COMM_PAGE_START_ADDRESS+0x028)        // used to be _COMM_PAGE_SCHED_GEN: uint32_t scheduler generation number (count of pre-emptions)
#define _COMM_PAGE_UNUSED3                      (_COMM_PAGE_START_ADDRESS+0x02C)        // used to be _COMM_PAGE_SPIN_COUNT: uint32_t max spin count for mutex's
#define _COMM_PAGE_MEMORY_PRESSURE              (_COMM_PAGE_START_ADDRESS+0x030)        // uint32_t copy of vm_memory_pressure
#define _COMM_PAGE_ACTIVE_CPUS                  (_COMM_PAGE_START_ADDRESS+0x034)        // uint8_t number of active CPUs (hw.activecpu)
#define _COMM_PAGE_PHYSICAL_CPUS                (_COMM_PAGE_START_ADDRESS+0x035)        // uint8_t number of physical CPUs (hw.physicalcpu_max)
#define _COMM_PAGE_LOGICAL_CPUS                 (_COMM_PAGE_START_ADDRESS+0x036)        // uint8_t number of logical CPUs (hw.logicalcpu_max)

#define _COMM_PAGE_KERNEL_PAGE_SHIFT_LEGACY     (_COMM_PAGE_START_ADDRESS+0x037)        // uint8_t kernel vm page shift */
#if _COMM_PAGE_LAYOUT_VERSION >= 1
#define _COMM_PAGE_KERNEL_PAGE_SHIFT            (_COMM_PAGE_RO_ADDRESS+0x037)           // uint8_t kernel vm page shift */
#else
#define _COMM_PAGE_KERNEL_PAGE_SHIFT            _COMM_PAGE_KERNEL_PAGE_SHIFT_LEGACY
#endif

#define _COMM_PAGE_MEMORY_SIZE                  (_COMM_PAGE_START_ADDRESS+0x038)        // uint64_t max memory size */
#define _COMM_PAGE_TIMEOFDAY_DATA               (_COMM_PAGE_START_ADDRESS+0x040)        // used by gettimeofday(). Currently, sizeof(commpage_timeofday_data_t) = 40. A new struct is used on gettimeofday but space is reserved on the commpage for compatibility
#define _COMM_PAGE_CPUFAMILY                    (_COMM_PAGE_START_ADDRESS+0x080)        // used by memcpy() resolver

#define _COMM_PAGE_DEV_FIRM_LEGACY              (_COMM_PAGE_START_ADDRESS+0x084)        // uint32_t handle on PE_i_can_has_debugger
#if _COMM_PAGE_LAYOUT_VERSION >= 1
#define _COMM_PAGE_DEV_FIRM                     (_COMM_PAGE_RO_ADDRESS+0x084)           // uint32_t handle on PE_i_can_has_debugger
#else
#define _COMM_PAGE_DEV_FIRM                     _COMM_PAGE_DEV_FIRM_LEGACY
#endif

#define _COMM_PAGE_TIMEBASE_OFFSET              (_COMM_PAGE_START_ADDRESS+0x088)        // uint64_t timebase offset for constructing mach_absolute_time()
#define _COMM_PAGE_USER_TIMEBASE                (_COMM_PAGE_START_ADDRESS+0x090)        // uint8_t is userspace mach_absolute_time supported (can read the timebase)
#define _COMM_PAGE_CONT_HWCLOCK                 (_COMM_PAGE_START_ADDRESS+0x091)        // uint8_t is always-on hardware clock present for mach_continuous_time()
#define _COMM_PAGE_DTRACE_DOF_ENABLED           (_COMM_PAGE_START_ADDRESS+0x092)        // uint8_t 0 if userspace DOF disable, 1 if enabled
#define _COMM_PAGE_UNUSED0                      (_COMM_PAGE_START_ADDRESS+0x093)        // 5 unused bytes
#define _COMM_PAGE_CONT_TIMEBASE                (_COMM_PAGE_START_ADDRESS+0x098)        // uint64_t base for mach_continuous_time() relative to mach_absolute_time()
#define _COMM_PAGE_BOOTTIME_USEC                (_COMM_PAGE_START_ADDRESS+0x0A0)        // uint64_t boottime in microseconds
#define _COMM_PAGE_CONT_HW_TIMEBASE             (_COMM_PAGE_START_ADDRESS+0x0A8)        // uint64_t base for mach_continuous_time() relative to CNT[PV]CT

// aligning to 64byte for cacheline size
#define _COMM_PAGE_APPROX_TIME                  (_COMM_PAGE_START_ADDRESS+0x0C0)        // uint64_t last known mach_absolute_time()
#define _COMM_PAGE_APPROX_TIME_SUPPORTED        (_COMM_PAGE_START_ADDRESS+0x0C8)        // uint8_t is mach_approximate_time supported


#define _COMM_PAGE_UNUSED1                      (_COMM_PAGE_START_ADDRESS+0x0D9)        // 39 unused bytes, align next mutable value to a separate cache line

#define _COMM_PAGE_KDEBUG_ENABLE                (_COMM_PAGE_START_ADDRESS+0x100)        // uint32_t export kdebug status bits to userspace
#define _COMM_PAGE_ATM_DIAGNOSTIC_CONFIG        (_COMM_PAGE_START_ADDRESS+0x104)        // uint32_t export "atm_diagnostic_config" to userspace
#define _COMM_PAGE_MULTIUSER_CONFIG             (_COMM_PAGE_START_ADDRESS+0x108)        // uint32_t export "multiuser_config" to userspace


#define _COMM_PAGE_NEWTIMEOFDAY_DATA            (_COMM_PAGE_START_ADDRESS+0x120)        // used by gettimeofday(). Currently, sizeof(new_commpage_timeofday_data_t) = 40.
#define _COMM_PAGE_REMOTETIME_PARAMS            (_COMM_PAGE_START_ADDRESS+0x148)        // used by mach_bridge_remote_time(). Currently, sizeof(struct bt_params) = 24
#define _COMM_PAGE_DYLD_FLAGS                   (_COMM_PAGE_START_ADDRESS+0x160)        // uint64_t export kern.dyld_system_flags to userspace

// aligning to 128 bytes for cacheline/fabric size
#define _COMM_PAGE_CPU_QUIESCENT_COUNTER        (_COMM_PAGE_START_ADDRESS+0x180)        // uint64_t, but reserve the whole 128 (0x80) bytes

#define _COMM_PAGE_END                          (_COMM_PAGE_START_ADDRESS+0xfff)        // end of common page

#if defined(__LP64__)
#if KERNEL_PRIVATE
#define _COMM_PAGE64_TEXT_START_ADDRESS          (_get_commpage_text_priv_address())      // Address through physical aperture
#endif
/* Offset in bytes from start of text comm page to get to these functions. Start
 * address to text comm page is from apple array */
#define _COMM_PAGE_TEXT_ATOMIC_ENQUEUE                  (0x0)
#define _COMM_PAGE_TEXT_ATOMIC_DEQUEUE                  (0x4)

#else /* __LP64__ */
/* No 32 bit text region */
#endif /* __LP64__ */

#endif /* defined (__arm__) || defined (__arm64__) */
#endif /* _ARM_CPU_CAPABILITIES_H */
#endif /* PRIVATE */
