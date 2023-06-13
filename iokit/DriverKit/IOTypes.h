/*
 * Copyright (c) 1998-2012 Apple Computer, Inc. All rights reserved.
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
#ifndef __IOKIT_IOTYPES_H
#define __IOKIT_IOTYPES_H

#ifndef XNU_PLATFORM_DriverKit

#ifndef IOKIT
#define IOKIT 1
#endif /* !IOKIT */

#include <sys/cdefs.h>

#if KERNEL
#include <IOKit/system.h>
#else
#include <mach/message.h>
#include <mach/vm_types.h>
#endif

#include <IOKit/IOReturn.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#if defined (__cplusplus)
#ifdef XNU_KERNEL_PRIVATE
#define NULL nullptr
#else
#if __cplusplus >= 201103L && (defined(__arm__) || defined(__arm64__))
#define NULL nullptr
#else
#define NULL    0
#endif
#endif
#else
#define NULL ((void *)0)
#endif
#endif

/*
 * Simple data types.
 */
#include <stdbool.h>
#include <libkern/OSTypes.h>

#if KERNEL
#include <libkern/OSBase.h>
#endif

typedef UInt32          IOOptionBits;
typedef SInt32          IOFixed;
typedef UInt32          IOVersion;
typedef UInt32          IOItemCount;
typedef UInt32          IOCacheMode;

typedef UInt32          IOByteCount32;
typedef UInt64          IOByteCount64;

typedef UInt32  IOPhysicalAddress32;
typedef UInt64  IOPhysicalAddress64;
typedef UInt32  IOPhysicalLength32;
typedef UInt64  IOPhysicalLength64;

#if !defined(__arm__) && !defined(__i386__)
typedef mach_vm_address_t       IOVirtualAddress __kernel_ptr_semantics;
#else
typedef vm_address_t            IOVirtualAddress __kernel_ptr_semantics;
#endif

#if !defined(__arm__) && !defined(__i386__) && !(defined(__x86_64__) && !defined(KERNEL)) && !(defined(__arm64__) && !defined(__LP64__))
typedef IOByteCount64           IOByteCount;
#define PRIIOByteCount                  PRIu64
#else
typedef IOByteCount32           IOByteCount;
#define PRIIOByteCount                  PRIu32
#endif

typedef IOVirtualAddress    IOLogicalAddress;

#if !defined(__arm__) && !defined(__i386__) && !(defined(__x86_64__) && !defined(KERNEL))

typedef IOPhysicalAddress64      IOPhysicalAddress;
typedef IOPhysicalLength64       IOPhysicalLength;
#define IOPhysical32( hi, lo )          ((UInt64) lo + ((UInt64)(hi) << 32))
#define IOPhysSize      64

#else

typedef IOPhysicalAddress32      IOPhysicalAddress;
typedef IOPhysicalLength32       IOPhysicalLength;
#define IOPhysical32( hi, lo )          (lo)
#define IOPhysSize      32

#endif


typedef struct{
	IOPhysicalAddress   address;
	IOByteCount         length;
} IOPhysicalRange;

typedef struct{
	IOVirtualAddress    address;
	IOByteCount         length;
} IOVirtualRange;

#if !defined(__arm__) && !defined(__i386__)
typedef IOVirtualRange  IOAddressRange;
#else
typedef struct{
	mach_vm_address_t   address;
	mach_vm_size_t      length;
} IOAddressRange;
#endif

/*
 * Map between #defined or enum'd constants and text description.
 */
typedef struct {
	int value;
	const char *name;
} IONamedValue;


/*
 * Memory alignment -- specified as a power of two.
 */
typedef unsigned int    IOAlignment;

#define IO_NULL_VM_TASK         ((vm_task_t)0)


/*
 * Pull in machine specific stuff.
 */

//#include <IOKit/machine/IOTypes.h>

#ifndef MACH_KERNEL

#ifndef __IOKIT_PORTS_DEFINED__
#define __IOKIT_PORTS_DEFINED__
#ifdef KERNEL
#ifdef __cplusplus
class OSObject;
typedef OSObject * io_object_t;
#else
typedef struct OSObject * io_object_t;
#endif
#else /* KERNEL */
typedef mach_port_t     io_object_t;
#endif /* KERNEL */
#endif /* __IOKIT_PORTS_DEFINED__ */

#include <device/device_types.h>

typedef io_object_t     io_connect_t;
typedef io_object_t     io_enumerator_t;
typedef io_object_t     io_ident_t;
typedef io_object_t     io_iterator_t;
typedef io_object_t     io_registry_entry_t;
typedef io_object_t     io_service_t;
typedef io_object_t     uext_object_t;

#define IO_OBJECT_NULL  ((io_object_t) 0)

#endif /* MACH_KERNEL */

#include <IOKit/IOMapTypes.h>

/*! @enum Scale Factors
 *   @discussion Used when a scale_factor parameter is required to define a unit of time.
 *   @constant kNanosecondScale Scale factor for nanosecond based times.
 *   @constant kMicrosecondScale Scale factor for microsecond based times.
 *   @constant kMillisecondScale Scale factor for millisecond based times.
 *   @constant kTickScale Scale factor for the standard (100Hz) tick.
 *   @constant kSecondScale Scale factor for second based times. */

enum {
	kNanosecondScale  = 1,
	kMicrosecondScale = 1000,
	kMillisecondScale = 1000 * 1000,
	kSecondScale      = 1000 * 1000 * 1000,
	kTickScale        = (kSecondScale / 100)
};

enum {
	kIOConnectMethodVarOutputSize = -3
};

/* compatibility types */

#ifndef KERNEL

typedef unsigned int IODeviceNumber;

#endif

#ifdef __cplusplus
}
#endif

#else /* !XNU_PLATFORM_DriverKit */

#include <stdint.h>

typedef uint32_t          IOOptionBits;
typedef int32_t           IOFixed;
typedef uint32_t          IOVersion;
typedef uint32_t          IOItemCount;
typedef uint32_t          IOCacheMode;

typedef uint32_t          IOByteCount32;
typedef uint64_t          IOByteCount64;
typedef IOByteCount64     IOByteCount;

typedef uint32_t  IOPhysicalAddress32;
typedef uint64_t  IOPhysicalAddress64;
typedef uint32_t  IOPhysicalLength32;
typedef uint64_t  IOPhysicalLength64;

typedef IOPhysicalAddress64      IOPhysicalAddress;
typedef IOPhysicalLength64       IOPhysicalLength;

typedef uint64_t       IOVirtualAddress;

#endif /* XNU_PLATFORM_DriverKit */

enum {
	kIOMaxBusStall40usec = 40000,
	kIOMaxBusStall30usec = 30000,
	kIOMaxBusStall25usec = 25000,
	kIOMaxBusStall20usec = 20000,
	kIOMaxBusStall10usec = 10000,
	kIOMaxBusStall5usec  = 5000,
	kIOMaxBusStallNone   = 0,
};

#if PRIVATE
#define LIBKERN_OSNUMBER_FLOAT_SUPPORT          1
#endif /* PRIVATE */

#endif /* ! __IOKIT_IOTYPES_H */
