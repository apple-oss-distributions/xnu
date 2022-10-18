/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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

#ifndef BSD_KDEBUG_PRIVATE_H
#define BSD_KDEBUG_PRIVATE_H

#include <os/base.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <sys/kdebug.h>

__BEGIN_DECLS

#if !KERNEL

#include <Availability.h>

#pragma mark - User space SPI

// Internal software can trace events into kdebug, but the os_signpost(3)
// interfaces in `<os/signpost.h>` are recommended.
//
//     kdebug_trace(KDBG_EVENTID(DBG_XPC, 15, 1), 1, 2, 3, 4);
//
// The performance impact when kernel tracing is not enabled is minimal.
// However, when tracing is enabled, each event requires a syscall.
//
// Classes can be reserved by filing a Radar in xnu | ktrace.
//
// 64-bit arguments may be truncated if the system is using a 32-bit kernel.
//
// On error, -1 will be returned and errno will indicate the error.
int kdebug_trace(uint32_t debugid, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    uint64_t arg4)
__API_AVAILABLE(macos(10.0), ios(8), tvos(8), watchos(1));

// Although the performance impact of kdebug_trace() when tracing is disabled is
// minimal, it may require the caller to perform an expensive calculation or
// summarization.  This cost can be skipped by checking the kdebug_is_enabled()
// predicate:
//
//     if (kdebug_is_enabled(KDBG_CODE(DBG_XPC, 15, 1))) {
//         uint64_t arg1 = ...;
//         uint64_t arg2 = ...;
//         kdebug_trace(KDBG_EVENTID(DBG_XPC, 15, 1), arg1, arg2, 0, 0);
//     }
//
// true is returned iff tracing is enabled for the debug ID at the time of the
// check.
extern bool kdebug_is_enabled(uint32_t debugid)
__API_AVAILABLE(macos(10.12), ios(10), watchos(3), tvos(10));

// Returns true if kdebug is using continuous time for its events, and false
// otherwise.
extern bool kdebug_using_continuous_time(void)
__API_AVAILABLE(macos(10.15), ios(13), tvos(13), watchos(6));

// Convert an absolute time to a kdebug timestamp.
extern uint64_t kdebug_timestamp_from_absolute(uint64_t abstime)
__API_AVAILABLE(macos(12), ios(15), tvos(15), watchos(8));

// Convert a continuous time to a kdebug timestamp.
extern uint64_t kdebug_timestamp_from_continuous(uint64_t conttime)
__API_AVAILABLE(macos(12), ios(15), tvos(15), watchos(8));

// Capture a kdebug timestamp for the current time.
extern uint64_t kdebug_timestamp(void)
__API_AVAILABLE(macos(12), ios(15), tvos(15), watchos(8));

/// @function kdebug_trace_string
///
/// @discussion
/// This function emits strings to kdebug trace along with an ID and allows
/// for previously-traced strings to be overwritten and invalidated.
///
/// To start tracing a string and generate an ID to use to refer to it:
///
///      string_id = kdebug_trace_string(debugid, 0, "string");
///
/// To replace a string previously traced:
///
///      string_id = kdebug_trace_string(debugid, string_id, "new string");
///
/// To invalidate a string ID:
///
///      string_id = kdebug_trace_string(debugid, string_id, NULL);
///
/// To check for errors:
///
///      if ((int64_t)string_id == -1) { perror("string error") }
///
/// @param debugid
/// The `debugid` to check if its enabled before tracing and include as
/// an argument in the event containing the string.
///
/// Some classes or subclasses are reserved for specific uses and are not
/// allowed to be used with this function.  No function qualifiers are
/// allowed on `debugid`.
///
/// @param str_id
/// When 0, a new ID will be generated and returned if tracing is
/// enabled.
///
/// Otherwise `str_id` must contain an ID that was previously generated
/// with this function.  Clents should pass NULL in `str` if `str_id`
/// is no longer in use.  Otherwise, the string previously mapped to
/// `str_id` will be overwritten with the contents of `str`.
///
/// @param str
/// A NUL-terminated 'C' string containing the characters that should be
/// traced alongside `str_id`.
///
/// If necessary, the string will be truncated at an
/// implementation-defined length of at least PATH_MAX characters.  The string
/// must not be the empty string, but can be NULL if a valid `str_id` is
/// provided.
///
/// @return
/// 0 if tracing is disabled or `debugid` is being filtered out of trace.
/// It can also return (int64_t)-1 if an error occured. Otherwise,
/// it returns the ID to use to refer to the string in future
/// kdebug_trace(2) calls.
///
/// The errors that can occur are:
///
/// EINVAL
///      There are function qualifiers on `debugid`, `str` is empty, or
///      `str_id` was not generated by this function.
/// EPERM
///      The `debugid`'s class or subclass is reserved for internal use.
/// EFAULT
///      `str` is an invalid address or NULL when `str_id` is 0.
extern uint64_t kdebug_trace_string(uint32_t debugid, uint64_t str_id,
    const char *str)
__API_AVAILABLE(macos(10.11), ios(9), watchos(2), tvos(9));

// Returns a pointer to the userspace typefilter, if one is available.
// May return NULL.
extern void *kdebug_typefilter(void)
__API_AVAILABLE(macos(10.12), ios(10), watchos(3), tvos(10));

#endif /* !KERNEL */

#pragma mark - Private debug IDs

#define DBG_PPT      36
#define DBG_PERFCTRL 39
#define DBG_CLPC     50
#define DBG_MUSE     52

#define DBG_ANS         128
#define DBG_SIO         129
#define DBG_SEP         130
#define DBG_ISP         131
#define DBG_OSCAR       132
#define DBG_EMBEDDEDGFX 133
#define DBG_PMP         134
#define DBG_RTKIT       135

// DBG_SKYWALK is the same as DBG_DLIL, so don't reuse subclasses
#define DBG_SKYWALK_ALWAYSON   0x10
#define DBG_SKYWALK_FLOWSWITCH 0x11
#define DBG_SKYWALK_NETIF      0x12
#define DBG_SKYWALK_CHANNEL    0x13
#define DBG_SKYWALK_PACKET     0x14

//DBG_AQM is the same as DBG_DLIL and DBG_SKYWALK, so don't reuse subclasses
#define DBG_AQM_ALWAYSON       0x30
#define DBG_AQM_STATS          0x31

// DBG_IFNET is the same as DBG_DLIL, DBG_AQM and DBG_SKYWALK, so don't reuse subclasses
#define DBG_IFNET              0x40

#define PPT_TEST           0x01
#define PPT_JETSAM_HIWAT   0x02
#define PPT_JETSAM_TOPPROC 0x03

#define SKYWALKDBG_CODE(SubClass, code) KDBG_CODE(DBG_DLIL, SubClass, code)
#define PPTDBG_CODE(SubClass, code) KDBG_CODE(DBG_PPT, SubClass, code)
#define PERFCTRL_CODE(SubClass, code) KDBG_CODE(DBG_PERFCTRL, SubClass, code)
#define AQMDBG_CODE(SubClass, code) KDBG_CODE(DBG_DLIL, SubClass, code)
#define IFNETDBG_CODE(SubClass, code) KDBG_CODE(DBG_DLIL, SubClass, code)

#if !defined(DRIVERKIT)

extern unsigned int kdebug_enable;

// Options for `kdebug_enable`.

// Enable tracing.
#define KDEBUG_ENABLE_TRACE     0x001U
// Whether timestamps are continuous times or absolute times.
#define KDEBUG_ENABLE_CONT_TIME 0x020U

#define KDEBUG_TRACE (KDEBUG_ENABLE_TRACE)

// Control which kernel events are compiled in under different build
// configurations.

// No kdebug events are emitted with the macros.
#define KDEBUG_LEVEL_NONE     0
// In-System Tracing exposes a limited set of events for release kernels.
#define KDEBUG_LEVEL_IST      1
// The default for development kernels.
#define KDEBUG_LEVEL_STANDARD 2
// Truly verbose, debug-level logging, only set manually.
#define KDEBUG_LEVEL_FULL     3

// Use configuration options to set the kdebug level.
#if NO_KDEBUG
#define KDEBUG_LEVEL KDEBUG_LEVEL_NONE
#elif IST_KDEBUG
#define KDEBUG_LEVEL KDEBUG_LEVEL_IST
#elif KDEBUG
#define KDEBUG_LEVEL KDEBUG_LEVEL_FULL
#else // !NO_KDEBUG && !IST_KDEBUG && !KDEBUG
#define KDEBUG_LEVEL KDEBUG_LEVEL_STANDARD
#endif // !NO_KDEBUG && !IST_KDEBUG && !KDEBUG

#pragma mark - Implementation details

// Ensure that LP32 and LP64 variants of arm64 use the same kd_buf structure.
#if defined(__arm64__)
typedef uint64_t kd_buf_argtype;
#else // defined(__arm64__)
typedef uintptr_t kd_buf_argtype;
#endif // !defined(__arm64__)

// The main event ABI as recorded in the kernel.

typedef struct {
	uint64_t timestamp;
	kd_buf_argtype arg1;
	kd_buf_argtype arg2;
	kd_buf_argtype arg3;
	kd_buf_argtype arg4;
	kd_buf_argtype arg5; // Always the thread ID.
	uint32_t debugid;
// Ensure that LP32 and LP64 variants of arm64 use the same kd_buf structure.
#if defined(__LP64__) || defined(__arm64__)
	uint32_t cpuid;
	kd_buf_argtype unused;
#endif // defined(__LP64__) || defined(__arm64__)
} kd_buf;

#if defined(__LP64__) || defined(__arm64__)

#define KDBG_TIMESTAMP_MASK 0xffffffffffffffffULL
static inline void
kdbg_set_cpu(kd_buf *kp, int cpu)
{
	kp->cpuid = (unsigned int)cpu;
}
static inline int
kdbg_get_cpu(kd_buf *kp)
{
	return (int)kp->cpuid;
}
static inline void
kdbg_set_timestamp(kd_buf *kp, uint64_t thetime)
{
	kp->timestamp = thetime;
}
static inline uint64_t
kdbg_get_timestamp(kd_buf *kp)
{
	return kp->timestamp;
}
static inline void
kdbg_set_timestamp_and_cpu(kd_buf *kp, uint64_t thetime, int cpu)
{
	kdbg_set_timestamp(kp, thetime);
	kdbg_set_cpu(kp, cpu);
}
#else // defined(__LP64__) || defined(__arm64__)
#define KDBG_TIMESTAMP_MASK 0x00ffffffffffffffULL
#define KDBG_CPU_MASK       0xff00000000000000ULL
#define KDBG_CPU_SHIFT      56
static inline void
kdbg_set_cpu(kd_buf *kp, int cpu)
{
	kp->timestamp = (kp->timestamp & KDBG_TIMESTAMP_MASK) |
	    (((uint64_t) cpu) << KDBG_CPU_SHIFT);
}
static inline int
kdbg_get_cpu(kd_buf *kp)
{
	return (int) (((kp)->timestamp & KDBG_CPU_MASK) >> KDBG_CPU_SHIFT);
}
static inline void
kdbg_set_timestamp(kd_buf *kp, uint64_t thetime)
{
	kp->timestamp = thetime & KDBG_TIMESTAMP_MASK;
}
static inline uint64_t
kdbg_get_timestamp(kd_buf *kp)
{
	return kp->timestamp & KDBG_TIMESTAMP_MASK;
}
static inline void
kdbg_set_timestamp_and_cpu(kd_buf *kp, uint64_t thetime, int cpu)
{
	kp->timestamp = (thetime & KDBG_TIMESTAMP_MASK) |
	    (((uint64_t) cpu) << KDBG_CPU_SHIFT);
}
#endif // !defined(__LP64__) && !defined(__arm64__)

// 8KB, one bit for each possible class/subclass combination.
#define KDBG_TYPEFILTER_BITMAP_SIZE ((256 * 256) / 8)

// Settings that may need to be changed while tracing, protected by the storage
// lock or the ktrace lock if tracing is disabled.
//
// These flags must not overlap with `kdebug_flags_t`.
__options_decl(kdebug_live_flags_t, uint32_t, {
	// Disable tracing when events wrap.  Set while reading events.
	KDBG_NOWRAP = 0x0002,
	// Events have wrapped.
	KDBG_WRAPPED = 0x0008,
});

// Mostly configuration options, protected by the ktrace lock.
__options_decl(kdebug_flags_t, uint32_t, {
	// Only trace processes with the kdebug bit set.
	KDBG_PIDCHECK = 0x0010,
	// Thread map pointer is valid.
	KDBG_MAPINIT = 0x0020,
	// Exclude events from processes with the kdebug bit set.
	KDBG_PIDEXCLUDE = 0x0040,
	// Events are 64-bit, only for `kbufinfo_t`.
	KDBG_LP64 = 0x0100,
	// Timestamps are continuous time, instead of absolute time.
	KDBG_CONTINUOUS_TIME = 0x0200,
	// Exclude events from coprocessors (IOPs).
	KDBG_DISABLE_COPROCS = 0x0400,
	// Disable tracing on event match.
	KDBG_MATCH_DISABLE = 0x0800,
	// Check the typefilter.
	KDBG_TYPEFILTER_CHECK = 0x00400000,
	// 64-bit debug ID present in arg4 (triage-only).
	KDBG_DEBUGID_64 = 0x00800000,
	// Event storage buffers are initialized.
	KDBG_BUFINIT = 0x80000000U,
});

// Obsolete flags.
#define KDBG_INIT    0x01
#define KDBG_FREERUN 0x04

// Flags in `kdebug_live_flags_t` and `kdebug_flags_t` that can be modified by
// user space.
#define KDBG_USERFLAGS (KDBG_NOWRAP | KDBG_CONTINUOUS_TIME | \
    KDBG_DISABLE_COPROCS | KDBG_MATCH_DISABLE)

// Information about kdebug for user space consumption.
typedef struct {
	// Size of buffers in number of events (kd_bufs).
	int nkdbufs;
	// True is tracing is disabled, false otherwise.
	int nolog;
	// Combined `kdebug_live_flags_t` and `kdebug_state_t`.
	unsigned int flags;
	// Number of threads in the thread map.
	int nkdthreads;
	// Owning process PID.
	int bufid;
} kbufinfo_t;

// Header for CPU mapping list.
typedef struct {
	uint32_t version_no;
	uint32_t cpu_count;
} kd_cpumap_header;

// CPU map entry flags.
#define KDBG_CPUMAP_IS_IOP 0x1

// CPU map entries to map `cpuid` from events to names.
typedef struct {
	uint32_t cpu_id;
	uint32_t flags;
	char name[32];
} kd_cpumap_ext;

// Match structured data from events.
typedef struct {
	uint32_t kem_debugid;
	uint32_t kem_padding;
	uint64_t kem_args[4];
} kd_event_matcher;

// Options for `kdebug_enable` in the comm-page.
#define KDEBUG_COMMPAGE_ENABLE_TRACE      0x1
#define KDEBUG_COMMPAGE_ENABLE_TYPEFILTER 0x2
#define KDEBUG_COMMPAGE_CONTINUOUS        0x4

#pragma mark - Tests

// Test scenarios.
__enum_decl(kdebug_test_t, uint32_t, {
	KDTEST_KERNEL_MACROS = 1,
	KDTEST_OLD_TIMESTAMP,
	KDTEST_FUTURE_TIMESTAMP,
	KDTEST_SETUP_IOP,
	KDTEST_SETUP_COPROCESSOR,
	KDTEST_CONTINUOUS_TIMESTAMP,
	KDTEST_ABSOLUTE_TIMESTAMP,
	KDTEST_PAST_EVENT,
});

#pragma mark - Obsolete interfaces

// Some Apple-internal clients try to use the kernel macros in user space.
#ifndef KERNEL_DEBUG
#define KERNEL_DEBUG(...) do { } while (0)
#endif // !defined(KERNEL_DEBUG)

// Obsolete options for `kdebug_enable`.
#define KDEBUG_ENABLE_ENTROPY   0x002U
#define KDEBUG_ENABLE_CHUD      0x004U
#define KDEBUG_ENABLE_PPT       0x008U
#define KDEBUG_ENABLE_SERIAL    0x010U
#define KDEBUG_PPT    (KDEBUG_ENABLE_PPT)
#define KDEBUG_COMMON (KDEBUG_ENABLE_TRACE | KDEBUG_ENABLE_PPT)

// Obsolete flags.
#define KDBG_LOCKINIT   0x0080
#define KDBG_RANGECHECK 0x00100000U
#define KDBG_VALCHECK   0x00200000U

// Type values for `kd_regtype`.
#define KDBG_CLASSTYPE  0x10000
#define KDBG_SUBCLSTYPE 0x20000
#define KDBG_RANGETYPE  0x40000
#define KDBG_TYPENONE   0x80000
#define KDBG_CKTYPES    0xF0000

typedef struct {
	unsigned int type;
	unsigned int value1;
	unsigned int value2;
	unsigned int value3;
	unsigned int value4;
} kd_regtype;

// Entry for the legacy thread map system (replaced by stackshot).
typedef struct {
	// A thread's unique ID.
#if defined(__arm64__)
	uint64_t thread;
#else
	uintptr_t thread __kernel_data_semantics;
#endif
	// The process ID (or 1 for `kernproc`).
	int valid;
	// The name of the process owning this thread.
	char command[20];
} kd_threadmap;

// Legacy CPU map entry.
typedef struct {
	uint32_t cpu_id;
	uint32_t flags;
	char name[8];
} kd_cpumap;

// File header for legacy trace files.
typedef struct {
	int version_no;
	int thread_count;
	uint64_t TOD_secs;
	uint32_t TOD_usecs;
} RAW_header;

// Obsolete `version_no` for legacy trace files.
#define RAW_VERSION0 0x55aa0000
#define RAW_VERSION1 0x55aa0101
#define RAW_VERSION2 0x55aa0200

// Obsolete EnergyTracing definitions.

#define kEnTrCompKernel 2
#define kEnTrActKernSocket 1
#define kEnTrActKernSockRead 2
#define kEnTrActKernSockWrite 3
#define kEnTrActKernPoll 10
#define kEnTrActKernSelect 11
#define kEnTrActKernKQWait 12
#define kEnTrEvUnblocked 256
#define kEnTrFlagNonBlocking 0x1
#define kEnTrFlagNoWork 0x2

#if (KDEBUG_LEVEL >= KDEBUG_LEVEL_IST)
#define ENTR_SHOULDTRACE kdebug_enable
#define ENTR_KDTRACE(component, opcode, lifespan, id, quality, value)  \
do {                                                                   \
    uint32_t kdcode__;                                                 \
    uintptr_t highval__, lowval__, mask__ = 0xffffffff;                \
    kdcode__ = KDBG_CODE(DBG_ENERGYTRACE,component,opcode)|(lifespan); \
    highval__ = ((value) >> 32) & mask__;                              \
    lowval__ = (value) & mask__;                                       \
    ENTR_KDTRACEFUNC(kdcode__, id, quality, highval__, lowval__);      \
} while(0)

#define kEnTrModAssociate (1 << 28)
#define ENTR_KDASSOCIATE(par_comp, par_opcode, par_act_id,           \
	    sub_comp, sub_opcode, sub_act_id)                            \
do {                                                                 \
    unsigned sub_compcode = ((unsigned)sub_comp << 16) | sub_opcode; \
    ENTR_KDTRACEFUNC(KDBG_CODE(DBG_ENERGYTRACE,par_comp,par_opcode), \
	             par_act_id, kEnTrModAssociate, sub_compcode,        \
	             sub_act_id);                                        \
} while(0)

#else // (KDEBUG_LEVEL >= KDEBUG_LEVEL_IST)

#define ENTR_SHOULDTRACE 0
#define ENTR_KDTRACE(component, opcode, lifespan, id, quality, value) do {} while (0)
#define ENTR_KDASSOCIATE(par_comp, par_opcode, par_act_id, sub_comp, sub_opcode, sub_act_id) do {} while (0)

#endif // (KDEBUG_LEVEL >= KDEBUG_LEVEL_IST)

#endif // !defined(DRIVERKIT)

__END_DECLS

#endif // !defined(BSD_KDEBUG_PRIVATE_H)
