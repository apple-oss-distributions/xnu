/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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

#ifndef XNU_LIBKERN_LIBKERN_CXX_OS_ALLOCATION_H
#define XNU_LIBKERN_LIBKERN_CXX_OS_ALLOCATION_H

#if !TAPI

#include <stddef.h>
#if DRIVERKIT_FRAMEWORK_INCLUDE
#include <DriverKit/OSBoundedPtr.h>
#include <DriverKit/safe_allocation.h>
#include <DriverKit/IOLib.h> // IOMalloc/IOFree
#else
#include <libkern/c++/OSBoundedPtr.h>
#include <libkern/c++/safe_allocation.h>
#include <IOKit/IOLib.h> // IOMalloc/IOFree
#endif /* DRIVERKIT_FRAMEWORK_INCLUDE */

namespace os_detail {
struct IOKit_allocator {
	static void*
	allocate(size_t bytes)
	{
		return IOMalloc(bytes);
	}

	static void*
	allocate_zero(size_t bytes)
	{
		return IOMallocZero(bytes);
	}

	static void
	deallocate(void* p, size_t bytes)
	{
		IOFree(p, bytes);
	}
};

#ifdef KERNEL_PRIVATE
struct IOKit_data_allocator {
	static void*
	allocate(size_t bytes)
	{
		return IOMallocData(bytes);
	}

	static void*
	allocate_zero(size_t bytes)
	{
		return IOMallocZeroData(bytes);
	}

	static void
	deallocate(void* p, size_t bytes)
	{
		IOFreeData(p, bytes);
	}
};
#endif
} // end namespace os_detail

template <typename T, typename Allocator = os_detail::IOKit_allocator>
using OSAllocation = libkern::safe_allocation<T, Allocator, os_detail::panic_trapping_policy>;

#ifdef KERNEL_PRIVATE
// uses IOMalloc(Zero)Data as underlying allocator (see IOKit/IOLib.h for advantages and restrictions)
template <typename T>
using OSDataAllocation = OSAllocation<T, os_detail::IOKit_data_allocator>;
#endif

inline constexpr auto OSAllocateMemory = libkern::allocate_memory;
inline constexpr auto OSAllocateMemoryZero = libkern::allocate_memory_zero;
inline constexpr auto OSAdoptMemory = libkern::adopt_memory;

#endif /* !TAPI */

#endif /* !XNU_LIBKERN_LIBKERN_CXX_OS_ALLOCATION_H */
