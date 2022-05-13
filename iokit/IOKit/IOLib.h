/*
 * Copyright (c) 1998-2016 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 */

#ifndef __IOKIT_IOLIB_H
#define __IOKIT_IOLIB_H

#ifndef KERNEL
#error IOLib.h is for kernel use only
#endif

#include <stdarg.h>
#include <sys/cdefs.h>
#include <os/overflow.h>
#include <os/alloc_util.h>

#include <sys/appleapiopts.h>

#include <IOKit/system.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOLocks.h>

#include <libkern/OSAtomic.h>

__BEGIN_DECLS

#include <kern/thread_call.h>
#include <kern/clock.h>
#ifdef KERNEL_PRIVATE
#include <kern/kalloc.h>
#include <kern/assert.h>
#endif

/*
 * min/max macros.
 */

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

/*
 * Safe functions to compute array sizes (saturate to a size that can't be
 * allocated ever and will cause the allocation to return NULL always).
 */

static inline vm_size_t
IOMallocArraySize(vm_size_t hdr_size, vm_size_t elem_size, vm_size_t elem_count)
{
	/* IOMalloc() will reject this size before even asking the VM  */
	const vm_size_t limit = 1ull << (8 * sizeof(vm_size_t) - 1);
	vm_size_t s = hdr_size;

	if (os_mul_and_add_overflow(elem_size, elem_count, s, &s) || (s & limit)) {
		return limit;
	}
	return s;
}

/*
 * These are opaque to the user.
 */
typedef thread_t IOThread;
typedef void (*IOThreadFunc)(void *argument);

/*
 * Memory allocation functions.
 */
#if XNU_KERNEL_PRIVATE

/*
 * IOMalloc_internal allocates memory from the specifed kalloc heap, which can be:
 * - KHEAP_DATA_BUFFERS: Should be used for data buffers
 * - KHEAP_DEFAULT: Should be used for allocations that aren't data buffers.
 *
 * For more details on kalloc_heaps see kalloc.h
 */

extern void *
IOMalloc_internal(
	struct kalloc_heap * kalloc_heap_cfg,
	vm_size_t            size,
	zalloc_flags_t       flags)     __attribute__((alloc_size(2)));

#define IOMalloc(size)     IOMalloc_internal(KHEAP_DEFAULT, size, Z_WAITOK)
#define IOMallocZero(size) IOMalloc_internal(KHEAP_DEFAULT, size, Z_ZERO)

#else /* XNU_KERNEL_PRIVATE */

/*! @function IOMalloc
 *   @abstract Allocates general purpose, wired memory in the kernel map.
 *   @discussion This is a general purpose utility to allocate memory in the kernel. There are no alignment guarantees given on the returned memory, and alignment may vary depending on the kernel configuration. This function may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param size Size of the memory requested.
 *   @result Pointer to the allocated memory, or zero on failure. */

void * IOMalloc(vm_size_t size)      __attribute__((alloc_size(1)));
void * IOMallocZero(vm_size_t size)  __attribute__((alloc_size(1)));

/*! @function IOFree
 *   @abstract Frees memory allocated with IOMalloc.
 *   @discussion This function frees memory allocated with IOMalloc, it may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param address Pointer to the allocated memory. Must be identical to result
 *   @of a prior IOMalloc.
 *   @param size Size of the memory allocated. Must be identical to size of
 *   @the corresponding IOMalloc */

#endif /* XNU_KERNEL_PRIVATE */

#if XNU_KERNEL_PRIVATE

/*
 * IOFree_internal allows specifying the kalloc heap to free the allocation
 * to
 */

extern void
IOFree_internal(
	struct kalloc_heap * kalloc_heap_cfg,
	void               * inAddress,
	vm_size_t            size);

#endif /* XNU_KERNEL_PRIVATE */

void   IOFree(void * address, vm_size_t size);

/*! @function IOMallocAligned
 *   @abstract Allocates wired memory in the kernel map, with an alignment restriction.
 *   @discussion This is a utility to allocate memory in the kernel, with an alignment restriction which is specified as a byte count. This function may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param size Size of the memory requested.
 *   @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bit 0-7 zero.
 *   @result Pointer to the allocated memory, or zero on failure. */

#if XNU_KERNEL_PRIVATE

extern void *
IOMallocAligned_internal(
	struct kalloc_heap * kalloc_heap_cfg,
	vm_size_t            size,
	vm_size_t            alignment,
	zalloc_flags_t       flags)        __attribute__((alloc_size(2)));

#define IOMallocAligned(size, alignment) \
	IOMallocAligned_internal(KHEAP_DEFAULT, size, alignment, Z_WAITOK)

#else /* XNU_KERNEL_PRIVATE */

void * IOMallocAligned(vm_size_t size, vm_offset_t alignment) __attribute__((alloc_size(1)));

#endif /* !XNU_KERNEL_PRIVATE */


/*! @function IOFreeAligned
 *   @abstract Frees memory allocated with IOMallocAligned.
 *   @discussion This function frees memory allocated with IOMallocAligned, it may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param address Pointer to the allocated memory.
 *   @param size Size of the memory allocated. */

#if XNU_KERNEL_PRIVATE

/*
 * IOFreeAligned_internal allows specifying the kalloc heap to free the
 * allocation to
 */

extern void
IOFreeAligned_internal(
	struct kalloc_heap * kalloc_heap_cfg,
	void               * address,
	vm_size_t            size);

#endif /* XNU_KERNEL_PRIVATE */

void   IOFreeAligned(void * address, vm_size_t size);

/*! @function IOMallocContiguous
 *   @abstract Deprecated - use IOBufferMemoryDescriptor. Allocates wired memory in the kernel map, with an alignment restriction and physically contiguous.
 *   @discussion This is a utility to allocate memory in the kernel, with an alignment restriction which is specified as a byte count, and will allocate only physically contiguous memory. The request may fail if memory is fragmented, and may cause large amounts of paging activity. This function may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param size Size of the memory requested.
 *   @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bits 0-7 zero.
 *   @param physicalAddress IOMallocContiguous returns the physical address of the allocated memory here, if physicalAddress is a non-zero pointer. The physicalAddress argument is deprecated and should be passed as NULL. To obtain the physical address for a memory buffer, use the IODMACommand class in conjunction with the IOMemoryDescriptor or IOBufferMemoryDescriptor classes.
 *   @result Virtual address of the allocated memory, or zero on failure. */

void * IOMallocContiguous(vm_size_t size, vm_size_t alignment,
    IOPhysicalAddress * physicalAddress) __attribute__((deprecated)) __attribute__((alloc_size(1)));

/*! @function IOFreeContiguous
 *   @abstract Deprecated - use IOBufferMemoryDescriptor. Frees memory allocated with IOMallocContiguous.
 *   @discussion This function frees memory allocated with IOMallocContiguous, it may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param address Virtual address of the allocated memory.
 *   @param size Size of the memory allocated. */

void   IOFreeContiguous(void * address, vm_size_t size) __attribute__((deprecated));


/*! @function IOMallocPageable
 *   @abstract Allocates pageable memory in the kernel map.
 *   @discussion This is a utility to allocate pageable memory in the kernel. This function may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param size Size of the memory requested.
 *   @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bits 0-7 zero.
 *   @result Pointer to the allocated memory, or zero on failure. */

void * IOMallocPageable(vm_size_t size, vm_size_t alignment) __attribute__((alloc_size(1)));

/*! @function IOMallocPageableZero
 *   @abstract Allocates pageable, zeroed memory in the kernel map.
 *   @discussion Same as IOMallocPageable but guarantees the returned memory will be zeroed.
 *   @param size Size of the memory requested.
 *   @param alignment Byte count of the alignment for the memory. For example, pass 256 to get memory allocated at an address with bits 0-7 zero.
 *   @result Pointer to the allocated memory, or zero on failure. */

void * IOMallocPageableZero(vm_size_t size, vm_size_t alignment) __attribute__((alloc_size(1)));

/*! @function IOFreePageable
 *   @abstract Frees memory allocated with IOMallocPageable.
 *   @discussion This function frees memory allocated with IOMallocPageable, it may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param address Virtual address of the allocated memory.
 *   @param size Size of the memory allocated. */

void IOFreePageable(void * address, vm_size_t size);

#if XNU_KERNEL_PRIVATE

#define IOMallocData(size)     IOMalloc_internal(KHEAP_DATA_BUFFERS, size, Z_WAITOK)
#define IOMallocZeroData(size) IOMalloc_internal(KHEAP_DATA_BUFFERS, size, Z_ZERO)

#elif KERNEL_PRIVATE /* XNU_KERNEL_PRIVATE */

/*! @function IOMallocData
 *   @abstract Allocates wired memory in the kernel map, from a separate section meant for pure data.
 *   @discussion Same as IOMalloc except that this function should be used for allocating pure data.
 *   @param size Size of the memory requested.
 *   @result Pointer to the allocated memory, or zero on failure. */
void * IOMallocData(vm_size_t size) __attribute__((alloc_size(1)));

/*! @function IOMallocZeroData
 *   @abstract Allocates wired memory in the kernel map, from a separate section meant for pure data bytes that don't contain pointers.
 *   @discussion Same as IOMallocData except that the memory returned is zeroed.
 *   @param size Size of the memory requested.
 *   @result Pointer to the allocated memory, or zero on failure. */
void * IOMallocZeroData(vm_size_t size) __attribute__((alloc_size(1)));

#endif /* KERNEL_PRIVATE */

#if KERNEL_PRIVATE

/*! @function IOFreeData
 *   @abstract Frees memory allocated with IOMallocData or IOMallocZeroData.
 *   @discussion This function frees memory allocated with IOMallocData/IOMallocZeroData, it may block and so should not be called from interrupt level or while a simple lock is held.
 *   @param address Virtual address of the allocated memory. Passing NULL here is acceptable.
 *   @param size Size of the memory allocated. It is acceptable to pass 0 size for a NULL address. */
void IOFreeData(void * address, vm_size_t size);

/*
 * Typed memory allocation macros. All may block.
 */

/*
 * Use IOMallocType to allocate a single typed object.
 *
 * If you use IONew with count 1, please use IOMallocType
 * instead. For arrays of typed objects use IONew.
 *
 * IOMallocType returns zeroed memory. It will not
 * fail to allocate memory for sizes less than:
 * - 16K (macos)
 * - 8K  (embedded 32-bit)
 * - 32K (embedded 64-bit)
 */
#define IOMallocType(type) ({                           \
	static KALLOC_TYPE_DEFINE(kt_view_var, type,        \
	    KT_SHARED_ACCT);                                \
	(type *) IOMallocTypeImpl(kt_view_var);             \
})

#define IOFreeType(elem, type) ({                       \
	static KALLOC_TYPE_DEFINE(kt_view_var, type,        \
	   KT_SHARED_ACCT);                                 \
	IOFREETYPE_ASSERT_COMPATIBLE_POINTER(elem, type);   \
	IOFreeTypeImpl(kt_view_var,                         \
	    os_ptr_load_and_erase(elem));                   \
})

#define IONewData(type, count) \
	((type *)IOMallocData(IOMallocArraySize(0, sizeof(type), count)))

#define IONewZeroData(type, count) \
	((type *)IOMallocZeroData(IOMallocArraySize(0, sizeof(type), count)))

#define IODeleteData(ptr, type, count) ({                \
	vm_size_t  __count = (vm_size_t)(count);             \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, type);       \
	IOFreeData(os_ptr_load_and_erase(ptr),               \
	    IOMallocArraySize(0, sizeof(type), __count));    \
})

/*
 * Versioning macro for the typed allocator APIs.
 */
#define IO_TYPED_ALLOCATOR_VERSION    1

#endif /* KERNEL_PRIVATE */

/*
 * IONew/IONewZero/IODelete/IOSafeDeleteNULL
 *
 * Those functions come in 2 variants:
 *
 * 1. IONew(element_type, count)
 *    IONewZero(element_type, count)
 *    IODelete(ptr, element_type, count)
 *    IOSafeDeleteNULL(ptr, element_type, count)
 *
 *    Those allocate/free arrays of `count` elements of type `element_type`.
 *
 * 2. IONew(hdr_type, element_type, count)
 *    IONewZero(hdr_type, element_type, count)
 *    IODelete(ptr, hdr_type, element_type, count)
 *    IOSafeDeleteNULL(ptr, hdr_type, element_type, count)
 *
 *    Those allocate/free arrays with `count` elements of type `element_type`,
 *    prefixed with a header of type `hdr_type`, like this:
 *
 * Those perform safe math with the sizes, checking for overflow.
 * An overflow in the sizes will cause the allocation to return NULL.
 */
#define IONew(...)             __IOKIT_DISPATCH(IONew, ##__VA_ARGS__)
#define IONewZero(...)         __IOKIT_DISPATCH(IONewZero, ##__VA_ARGS__)
#define IODelete(...)          __IOKIT_DISPATCH(IODelete, ##__VA_ARGS__)
#define IOSafeDeleteNULL(...)  __IOKIT_DISPATCH(IOSafeDeleteNULL, ##__VA_ARGS__)

#if KERNEL_PRIVATE
#define IONew_2(e_ty, count) ({                                             \
	static KALLOC_TYPE_VAR_DEFINE(kt_view_var, e_ty, KT_SHARED_ACCT);       \
	(e_ty *) IOMallocTypeVarImpl(kt_view_var,                               \
	    IOMallocArraySize(0, sizeof(e_ty), count));                         \
})

#define IONew_3(h_ty, e_ty, count) ({                                       \
	static KALLOC_TYPE_VAR_DEFINE(kt_view_var, h_ty, e_ty, KT_SHARED_ACCT); \
	(h_ty *) IOMallocTypeVarImpl(kt_view_var,                               \
	    IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count));              \
})

#define IONewZero_2(e_ty, count) \
	IONew_2(e_ty, count)

#define IONewZero_3(h_ty, e_ty, count) \
	IONew_3(h_ty, e_ty, count)

#else /* KERNEL_PRIVATE */
#define IONew_2(e_ty, count) \
	((e_ty *)IOMalloc(IOMallocArraySize(0, sizeof(e_ty), count)))

#define IONew_3(h_ty, e_ty, count) \
	((h_ty *)IOMalloc(IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count)))

#define IONewZero_2(e_ty, count) \
	((e_ty *)IOMallocZero(IOMallocArraySize(0, sizeof(e_ty), count)))

#define IONewZero_3(h_ty, e_ty, count) \
	((h_ty *)IOMallocZero(IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count)))
#endif /* !KERNEL_PRIVATE */

#if KERNEL_PRIVATE
#define IODelete_3(ptr, e_ty, count) ({                                     \
	vm_size_t __s = IOMallocArraySize(0, sizeof(e_ty), count);              \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, e_ty);                          \
	static KALLOC_TYPE_VAR_DEFINE(kt_view_var, e_ty, KT_SHARED_ACCT);       \
	IOFreeTypeVarImpl(kt_view_var, ptr, __s);                               \
})

#define IODelete_4(ptr, h_ty, e_ty, count) ({                               \
	vm_size_t __s = IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count);   \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, h_ty);                          \
	static KALLOC_TYPE_VAR_DEFINE(kt_view_var, h_ty, e_ty, KT_SHARED_ACCT); \
	IOFreeTypeVarImpl(kt_view_var, ptr, __s);                               \
})

#define IOSafeDeleteNULL_3(ptr, e_ty, count) ({                             \
	vm_size_t __s = IOMallocArraySize(0, sizeof(e_ty), count);              \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, e_ty);                          \
	static KALLOC_TYPE_VAR_DEFINE(kt_view_var, e_ty, KT_SHARED_ACCT);       \
	IOFreeTypeVarImpl(kt_view_var, os_ptr_load_and_erase(ptr), __s);        \
})

#define IOSafeDeleteNULL_4(ptr, h_ty, e_ty, count) ({                       \
	vm_size_t __s = IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count);   \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, h_ty);                          \
	static KALLOC_TYPE_VAR_DEFINE(kt_view_var, h_ty, e_ty, KT_SHARED_ACCT); \
	IOFreeTypeVarImpl(kt_view_var, os_ptr_load_and_erase(ptr), __s);        \
})

#else /* KERNEL_PRIVATE */
#define IODelete_3(ptr, e_ty, count) ({                      \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, e_ty);           \
	IOFree(ptr, IOMallocArraySize(0, sizeof(e_ty), count));  \
})

#define IODelete_4(ptr, h_ty, e_ty, count) ({                           \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, e_ty);                      \
	IOFree(ptr, IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count));  \
})

#define IOSafeDeleteNULL_3(ptr, e_ty, count)  ({                           \
	vm_size_t __s = IOMallocArraySize(0, sizeof(e_ty), count);             \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, e_ty);                         \
	IOFree(os_ptr_load_and_erase(ptr), __s);                               \
})

#define IOSafeDeleteNULL_4(ptr, h_ty, e_ty, count)  ({                     \
	vm_size_t __s = IOMallocArraySize(sizeof(h_ty), sizeof(e_ty), count);  \
	IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, h_ty);                         \
	IOFree(os_ptr_load_and_erase(ptr), __s);                               \
})
#endif /* !KERNEL_PRIVATE */

/////////////////////////////////////////////////////////////////////////////
//
//
//	These functions are now implemented in IOMapper.cpp
//
//
/////////////////////////////////////////////////////////////////////////////

/*! @function IOMappedRead8
 *   @abstract Read one byte from the desired "Physical" IOSpace address.
 *   @discussion Read one byte from the desired "Physical" IOSpace address.  This function allows the developer to read an address returned from any memory descriptor's getPhysicalSegment routine.  It can then be used by segmenting a physical page slightly to tag the physical page with its kernel space virtual address.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @result Data contained at that location */

UInt8 IOMappedRead8(IOPhysicalAddress address);

/*! @function IOMappedRead16
 *   @abstract Read two bytes from the desired "Physical" IOSpace address.
 *   @discussion Read two bytes from the desired "Physical" IOSpace address.  This function allows the developer to read an address returned from any memory descriptor's getPhysicalSegment routine.  It can then be used by segmenting a physical page slightly to tag the physical page with its kernel space virtual address.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @result Data contained at that location */

UInt16 IOMappedRead16(IOPhysicalAddress address);

/*! @function IOMappedRead32
 *   @abstract Read four bytes from the desired "Physical" IOSpace address.
 *   @discussion Read four bytes from the desired "Physical" IOSpace address.  This function allows the developer to read an address returned from any memory descriptor's getPhysicalSegment routine.  It can then be used by segmenting a physical page slightly to tag the physical page with its kernel space virtual address.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @result Data contained at that location */

UInt32 IOMappedRead32(IOPhysicalAddress address);

/*! @function IOMappedRead64
 *   @abstract Read eight bytes from the desired "Physical" IOSpace address.
 *   @discussion Read eight bytes from the desired "Physical" IOSpace address.  This function allows the developer to read an address returned from any memory descriptor's getPhysicalSegment routine.  It can then be used by segmenting a physical page slightly to tag the physical page with its kernel space virtual address.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @result Data contained at that location */

UInt64 IOMappedRead64(IOPhysicalAddress address);

/*! @function IOMappedWrite8
 *   @abstract Write one byte to the desired "Physical" IOSpace address.
 *   @discussion Write one byte to the desired "Physical" IOSpace address.  This function allows the developer to write to an address returned from any memory descriptor's getPhysicalSegment routine.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @param value Data to be writen to the desired location */

void IOMappedWrite8(IOPhysicalAddress address, UInt8 value);

/*! @function IOMappedWrite16
 *   @abstract Write two bytes to the desired "Physical" IOSpace address.
 *   @discussion Write two bytes to the desired "Physical" IOSpace address.  This function allows the developer to write to an address returned from any memory descriptor's getPhysicalSegment routine.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @param value Data to be writen to the desired location */

void IOMappedWrite16(IOPhysicalAddress address, UInt16 value);

/*! @function IOMappedWrite32
 *   @abstract Write four bytes to the desired "Physical" IOSpace address.
 *   @discussion Write four bytes to the desired "Physical" IOSpace address.  This function allows the developer to write to an address returned from any memory descriptor's getPhysicalSegment routine.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @param value Data to be writen to the desired location */

void IOMappedWrite32(IOPhysicalAddress address, UInt32 value);

/*! @function IOMappedWrite64
 *   @abstract Write eight bytes to the desired "Physical" IOSpace address.
 *   @discussion Write eight bytes to the desired "Physical" IOSpace address.  This function allows the developer to write to an address returned from any memory descriptor's getPhysicalSegment routine.
 *   @param address The desired address, as returned by IOMemoryDescriptor::getPhysicalSegment.
 *   @param value Data to be writen to the desired location */

void IOMappedWrite64(IOPhysicalAddress address, UInt64 value);

/* This function is deprecated. Cache settings may be set for allocated memory with the IOBufferMemoryDescriptor api. */

IOReturn IOSetProcessorCacheMode( task_t task, IOVirtualAddress address,
    IOByteCount length, IOOptionBits cacheMode ) __attribute__((deprecated));

/*! @function IOFlushProcessorCache
 *   @abstract Flushes the processor cache for mapped memory.
 *   @discussion This function flushes the processor cache of an already mapped memory range. Note in most cases it is preferable to use IOMemoryDescriptor::prepare and complete to manage cache coherency since they are aware of the architecture's requirements. Flushing the processor cache is not required for coherency in most situations.
 *   @param task Task the memory is mapped into.
 *   @param address Virtual address of the memory.
 *   @param length Length of the range to set.
 *   @result An IOReturn code. */

IOReturn IOFlushProcessorCache( task_t task, IOVirtualAddress address,
    IOByteCount length );

/*! @function IOThreadSelf
 *   @abstract Returns the osfmk identifier for the currently running thread.
 *   @discussion This function returns the current thread (a pointer to the currently active osfmk thread_shuttle). */

#define IOThreadSelf() (current_thread())

/*! @function IOCreateThread
 *   @abstract Deprecated function - use kernel_thread_start(). Create a kernel thread.
 *   @discussion This function creates a kernel thread, and passes the caller supplied argument to the new thread.  Warning: the value returned by this function is not 100% reliable.  There is a race condition where it is possible that the new thread has already terminated before this call returns.  Under that circumstance the IOThread returned will be invalid.  In general there is little that can be done with this value except compare it against 0.  The thread itself can call IOThreadSelf() 100% reliably and that is the prefered mechanism to manipulate the IOThreads state.
 *   @param function A C-function pointer where the thread will begin execution.
 *   @param argument Caller specified data to be passed to the new thread.
 *   @result An IOThread identifier for the new thread, equivalent to an osfmk thread_t. */

IOThread IOCreateThread(IOThreadFunc function, void *argument) __attribute__((deprecated));

/*! @function IOExitThread
 *   @abstract Deprecated function - use thread_terminate(). Terminate execution of current thread.
 *   @discussion This function destroys the currently running thread, and does not return. */

void IOExitThread(void) __attribute__((deprecated));

/*! @function IOSleep
 *   @abstract Sleep the calling thread for a number of milliseconds.
 *   @discussion This function blocks the calling thread for at least the number of specified milliseconds, giving time to other processes.
 *   @param milliseconds The integer number of milliseconds to wait. */

void IOSleep(unsigned milliseconds);

/*! @function IOSleepWithLeeway
 *   @abstract Sleep the calling thread for a number of milliseconds, with a specified leeway the kernel may use for timer coalescing.
 *   @discussion This function blocks the calling thread for at least the number of specified milliseconds, giving time to other processes.  The kernel may also coalesce any timers involved in the delay, using the leeway given as a guideline.
 *   @param intervalMilliseconds The integer number of milliseconds to wait.
 *   @param leewayMilliseconds The integer number of milliseconds to use as a timer coalescing guideline. */

void IOSleepWithLeeway(unsigned intervalMilliseconds, unsigned leewayMilliseconds);

/*! @function IODelay
 *   @abstract Spin delay for a number of microseconds.
 *   @discussion This function spins to delay for at least the number of specified microseconds. Since the CPU is busy spinning no time is made available to other processes; this method of delay should be used only for short periods. Also, the AbsoluteTime based APIs of kern/clock.h provide finer grained and lower cost delays.
 *   @param microseconds The integer number of microseconds to spin wait. */

void IODelay(unsigned microseconds);

/*! @function IOPause
 *   @abstract Spin delay for a number of nanoseconds.
 *   @discussion This function spins to delay for at least the number of specified nanoseconds. Since the CPU is busy spinning no time is made available to other processes; this method of delay should be used only for short periods.
 *   @param nanoseconds The integer number of nanoseconds to spin wait. */

void IOPause(unsigned nanoseconds);

/*! @function IOLog
 *   @abstract Log a message to console in text mode, and /var/log/system.log.
 *   @discussion This function allows a driver to log diagnostic information to the screen during verbose boots, and to a log file found at /var/log/system.log. IOLog should not be called from interrupt context.
 *   @param format A printf() style format string (see printf(3) documentation).
 */

void IOLog(const char *format, ...)
__attribute__((format(printf, 1, 2)));

/*! @function IOLogv
 *   @abstract Log a message to console in text mode, and /var/log/system.log.
 *   @discussion This function allows a driver to log diagnostic information to the screen during verbose boots, and to a log file found at /var/log/system.log. IOLogv should not be called from interrupt context.
 *   @param format A printf() style format string (see printf(3) documentation).
 *   @param ap stdarg(3) style variable arguments. */

void IOLogv(const char *format, va_list ap)
__attribute__((format(printf, 1, 0)));

#ifndef _FN_KPRINTF
#define _FN_KPRINTF
void kprintf(const char *format, ...) __printflike(1, 2);
#endif
#ifndef _FN_KPRINTF_DECLARED
#define _FN_KPRINTF_DECLARED
#endif

/*
 * Convert a integer constant (typically a #define or enum) to a string
 * via an array of IONamedValue.
 */
const char *IOFindNameForValue(int value,
    const IONamedValue *namedValueArray);

/*
 * Convert a string to an int via an array of IONamedValue. Returns
 * kIOReturnSuccess of string found, else returns kIOReturnBadArgument.
 */
IOReturn IOFindValueForName(const char *string,
    const IONamedValue *regValueArray,
    int *value);                                /* RETURNED */

/*! @function Debugger
 *   @abstract Enter the kernel debugger.
 *   @discussion This function freezes the kernel and enters the builtin debugger. It may not be possible to exit the debugger without a second machine.
 *   @param reason A C-string to describe why the debugger is being entered. */

void Debugger(const char * reason);
#if __LP64__
#define IOPanic(reason) panic("%s", reason)
#else
void IOPanic(const char *reason) __attribute__((deprecated)) __abortlike;
#endif

#ifdef __cplusplus
class OSDictionary;
#endif

#ifdef __cplusplus
OSDictionary *
#else
struct OSDictionary *
#endif
IOBSDNameMatching( const char * name );

#ifdef __cplusplus
OSDictionary *
#else
struct OSDictionary *
#endif
IOOFPathMatching( const char * path, char * buf, int maxLen ) __attribute__((deprecated));

/*
 * Convert between size and a power-of-two alignment.
 */
IOAlignment IOSizeToAlignment(unsigned int size);
unsigned int IOAlignmentToSize(IOAlignment align);

/*
 * Multiply and divide routines for IOFixed datatype.
 */

static inline IOFixed
IOFixedMultiply(IOFixed a, IOFixed b)
{
	return (IOFixed)((((SInt64) a) * ((SInt64) b)) >> 16);
}

static inline IOFixed
IOFixedDivide(IOFixed a, IOFixed b)
{
	return (IOFixed)((((SInt64) a) << 16) / ((SInt64) b));
}

/*
 * IORound and IOTrunc convenience functions, in the spirit
 * of vm's round_page() and trunc_page().
 */
#define IORound(value, multiple) \
	((((value) + (multiple) - 1) / (multiple)) * (multiple))

#define IOTrunc(value, multiple) \
	(((value) / (multiple)) * (multiple));


#if defined(__APPLE_API_OBSOLETE)

/* The following API is deprecated */

/* The API exported by kern/clock.h
 *  should be used for high resolution timing. */

void IOGetTime( mach_timespec_t * clock_time) __attribute__((deprecated));

#if !defined(__LP64__)

#undef eieio
#define eieio() \
    OSSynchronizeIO()

extern mach_timespec_t IOZeroTvalspec;

#endif /* !defined(__LP64__) */

#endif /* __APPLE_API_OBSOLETE */

#if XNU_KERNEL_PRIVATE
vm_tag_t
IOMemoryTag(vm_map_t map);

vm_size_t
log2up(vm_size_t size);
#endif

/*
 * Implementation details
 */
#define __IOKIT_COUNT_ARGS1(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, N, ...) N
#define __IOKIT_COUNT_ARGS(...) \
	__IOKIT_COUNT_ARGS1(, ##__VA_ARGS__, _9, _8, _7, _6, _5, _4, _3, _2, _1, _0)
#define __IOKIT_DISPATCH1(base, N, ...) __CONCAT(base, N)(__VA_ARGS__)
#define __IOKIT_DISPATCH(base, ...) \
	__IOKIT_DISPATCH1(base, __IOKIT_COUNT_ARGS(__VA_ARGS__), ##__VA_ARGS__)


#ifdef XNU_KERNEL_PRIVATE

#define IOFREETYPE_ASSERT_COMPATIBLE_POINTER(ptr, type) \
    KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(ptr, type)

#define IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, type) \
    KALLOC_TYPE_ASSERT_COMPATIBLE_POINTER(ptr, type)

#else  /* XNU_KERNEL_PRIVATE */

#define IOFREETYPE_ASSERT_COMPATIBLE_POINTER(ptr, type) do {} while (0)
#define IODELETE_ASSERT_COMPATIBLE_POINTER(ptr, type) do {} while (0)

#endif /* XNU_KERNEL_PRIVATE */

#if KERNEL_PRIVATE
/*
 * Implementation functions for IOMallocType/IOFreeType.
 * Not intended to be used on their own.
 */
void *
IOMallocTypeImpl(kalloc_type_view_t kt_view);

void
IOFreeTypeImpl(kalloc_type_view_t kt_view, void * address);

void *
IOMallocTypeVarImpl(kalloc_type_var_view_t kt_view, vm_size_t size);

void
IOFreeTypeVarImpl(kalloc_type_var_view_t kt_view, void * address, vm_size_t size);
#endif

#if KERNEL_PRIVATE
#if __cplusplus

#if __has_feature(cxx_deleted_functions)
#define __IODeleteArrayOperators()                         \
	_Pragma("clang diagnostic push")                       \
	_Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
	void *operator new[](size_t) = delete;                 \
	void operator delete[](void *) = delete;               \
	void operator delete[](void *, size_t) = delete;       \
	_Pragma("clang diagnostic pop")
#else  /* __has_feature(cxx_deleted_functions) */
#define __IODeleteArrayOperators()
#endif /* __has_feature(cxx_deleted_functions) */

#define __IOAddOperatorsSentinel(name, type) \
	static void __CONCAT(name, type) (void) __unused

#define __IOAddTypedOperatorsSentinel(type) \
	__IOAddOperatorsSentinel(__kt_typed_operators_, type)

#define __IOAddTypedArrayOperatorsSentinel(type) \
	__IOAddOperatorsSentinel(__kt_typed_array_operators_, type)

#define __IODeclareTypedOperators(type)                    \
	void *operator new(size_t size __unused);              \
	void operator delete(void *mem, size_t size __unused); \
	__IOAddTypedOperatorsSentinel(type)

#define __IODeclareTypedArrayOperators(type) \
	void *operator new[](size_t __unused);   \
	void operator delete[](void *ptr);       \
	__IOAddTypedArrayOperatorsSentinel(type)


#define __IODefineTypedOperators(type)                          \
	void *type::operator new(size_t size __unused)              \
	{                                                           \
	        return IOMallocType(type);                                \
	}                                                           \
	void type::operator delete(void *mem, size_t size __unused) \
	{                                                           \
	        IOFreeType(mem, type);                                    \
	}

struct __IOTypedOperatorsArrayHeader {
	size_t esize;
	size_t count;
};

#define __IOTypedOperatorNewArrayImpl(type, count)                \
	{                                                             \
	__IOTypedOperatorsArrayHeader *hdr;                        \
	hdr = IONew(__IOTypedOperatorsArrayHeader, type, count);   \
	if (hdr) {                                                 \
	        hdr->esize = sizeof(type);                             \
	        hdr->count = count;                                    \
	        return static_cast<void *>(&hdr[1]);                   \
	}                                                          \
	_Pragma("clang diagnostic push")                           \
	_Pragma("clang diagnostic ignored \"-Wnew-returns-null\"") \
	return NULL;                                               \
	_Pragma("clang diagnostic pop")                            \
	}

#define __IOTypedOperatorDeleteArrayImpl(type, ptr)                      \
	{                                                                    \
	        __IOTypedOperatorsArrayHeader *hdr;                               \
	        uintptr_t uptr = reinterpret_cast<uintptr_t>(ptr) - sizeof(*hdr); \
	        hdr = reinterpret_cast<__IOTypedOperatorsArrayHeader *>(uptr);    \
	        IODelete(hdr, __IOTypedOperatorsArrayHeader, type, hdr->count);   \
	}

#define __IODefineTypedArrayOperators(type)        \
	void *type::operator new[](size_t count)       \
	__IOTypedOperatorNewArrayImpl(type, count)  \
	void type::operator delete[](void *ptr)        \
	__IOTypedOperatorDeleteArrayImpl(type, ptr)


#define __IOOverrideTypedOperators(type)                  \
	void *operator new(size_t size __unused)              \
	{                                                     \
	        return IOMallocType(type);                        \
	}                                                     \
	void operator delete(void *mem, size_t size __unused) \
	{                                                     \
	        IOFreeType(mem, type);                            \
	} \
	__IOAddTypedOperatorsSentinel(type)

#define __IOOverrideTypedArrayOperators(type)       \
	void *operator new[](size_t count)              \
	__IOTypedOperatorNewArrayImpl(type, count)   \
	void operator delete[](void *ptr)               \
	__IOTypedOperatorDeleteArrayImpl(type, ptr)  \
	__IOAddTypedArrayOperatorsSentinel(type)

/*!
 * @macro IODeclareTypedOperators
 *
 * @abstract
 * Declare operator new/delete to adopt the typed allocator
 * API for a given class/struct. It must be paired with
 * @c IODefineTypedOperators.
 *
 * @discussion
 * Use this macro within a class/struct declaration to declare
 * @c operator new and @c operator delete to use the typed
 * allocator API as the backing storage for this type.
 *
 * @note The default variant deletes the declaration of the
 * array operators. Please see doc/allocators/api-basics.md for
 * more details regarding their usage.
 *
 * @param type The type which the declarations are being provided for.
 */
#define IODeclareTypedOperatorsSupportingArrayOperators(type) \
	__IODeclareTypedArrayOperators(type);                     \
	__IODeclareTypedOperators(type)
#define IODeclareTypedOperators(type) \
	__IODeleteArrayOperators()        \
	__IODeclareTypedOperators(type)

/*!
 * @macro IODefineTypedOperators
 *
 * @abstract
 * Define (out of line) operator new/delete to adopt the typed
 * allocator API for a given class/struct. It must be paired
 * with @c IODeclareTypedOperators.
 *
 * @discussion
 * Use this macro to provide an out of line definition of
 * @c operator new and @c operator delete for a given type
 * to use the typed allocator API as its backing storage.
 *
 * @param type The type which the overrides are being provided for.
 */
#define IODefineTypedOperatorsSupportingArrayOperators(type) \
	__IODefineTypedOperators(type)                           \
	__IODefineTypedArrayOperators(type)
#define IODefineTypedOperators(type) \
	__IODefineTypedOperators(type)

/*!
 * @macro IOOverrideTypedOperators
 *
 * @abstract
 * Override operator new/delete to use @c kalloc_type.
 *
 * @discussion
 * Use this macro within a class/struct declaration to override
 * @c operator new and @c operator delete to use the typed
 * allocator API as the backing storage for this type.
 *
 * @note The default variant deletes the implementation of the
 * array operators. Please see doc/allocators/api-basics.md for
 * more details regarding their usage.
 *
 * @param type The type which the overrides are being provided for.
 */
#define IOOverrideTypedOperators(type) \
	__IODeleteArrayOperators()         \
	__IOOverrideTypedOperators(type)

#define IOOverrideTypedOperatorsSupportingArrayOperators(type) \
	__IOOverrideTypedArrayOperators(type);                     \
	__IOOverrideTypedOperators(type)


extern "C++" {
/*!
 * @template IOTypedOperatorsMixin
 *
 * @abstract
 * Mixin that implements @c operator new and @c operator delete
 * using the typed allocator API.
 *
 * @discussion
 * Inherit from this struct in order to adopt the typed allocator
 * API on a struct/class for @c operator new and @c operator delete.
 *
 * The type passed as as a template parameter must be the type
 * which is inheriting from the struct itself.
 *
 * @note See doc/allocators/api-basics.md for more details
 * regarding the usage of the mixin.
 *
 * @example
 *
 *     class C : public IOTypedOperatorsMixin<C> {
 *         ...
 *     }
 *     C *obj = new C;
 *
 */
template<class T>
struct IOTypedOperatorsMixin {
	IOOverrideTypedOperators(T);
};

template<class T>
struct IOTypedOperatorsMixinSupportingArrayOperators {
	IOOverrideTypedOperatorsSupportingArrayOperators(T);
};
} // extern "C++"


#endif /* __cplusplus */
#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif /* !__IOKIT_IOLIB_H */
