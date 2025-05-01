/* * Copyright (c) 2018 Apple Inc. All rights reserved.
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


#ifndef _OS_CXX_SAFE_BUFFERS_H
#define _OS_CXX_SAFE_BUFFERS_H

#ifdef KERNEL_PRIVATE
 #include <kern/kalloc.h>
#endif

#if (defined(__has_include) && __has_include(<span>) && __has_include(<iterator>) && __has_include(<type_traits>))
#include <iterator>
#include <span>
#include <type_traits>

namespace os {
#pragma clang unsafe_buffer_usage begin
/* The `unsafe_forge_span` functions are for suppressing false
 *  positive `-Wunsafe-buffer-usage-in-container` warnings on
 *  uses of the two-parameter `std::span` constructors.
 *
 *  For a `std::span(ptr, size)` call that raises a false alarm, one
 *  can suppress the warning by changing the call to
 *  `unsafe_forge_span(ptr, size)`.
 *
 *  Please consider the C++ Safe Buffers Programming Model and
 *  Adoption Tooling Guide as a reference to identify false positives
 *  and do not use the functions in non-applicable cases.
 */
template<std::contiguous_iterator It>
std::span<std::remove_reference_t<std::iter_reference_t<It> > >
unsafe_forge_span(It data, typename std::span<std::remove_reference_t<std::iter_reference_t<It> > >::size_type size)
{
	return std::span<std::remove_reference_t<std::iter_reference_t<It> > >{data, size};
}

template<std::contiguous_iterator It, std::sized_sentinel_for<It> End>
std::span<std::remove_reference_t<std::iter_reference_t<It> > >
unsafe_forge_span(It begin, End end)
{
	return std::span<std::remove_reference_t<std::iter_reference_t<It> > >{begin, end};
}

template<typename T, std::size_t N>
std::span<T, N>
unsafe_forge_span(T *data)
{
	return std::span<T, N>{data, N};
}

template<
	typename Dst,
	typename Src,
	std::size_t Count
#ifdef KERNEL_PRIVATE
	, typename = std::enable_if_t<KALLOC_TYPE_IS_DATA_ONLY(Src) && KALLOC_TYPE_IS_DATA_ONLY(Dst)>
#endif
	>
std::span<Dst, Count == std::dynamic_extent
    ? std::dynamic_extent
    : (Count * sizeof(Src)) / sizeof(Dst)>
reinterpret_span_cast( std::span<Src, Count> src )
{
	if constexpr (std::is_same_v<Dst, std::byte>) {
		return std::as_writable_bytes(src);
	} else {
		if constexpr (std::is_same_v<Dst, const std::byte>) {
			return std::as_bytes(src);
		}
	}

	if constexpr (Count == std::dynamic_extent) {
		if constexpr ((sizeof(Src) < sizeof(Dst)) || (sizeof(Src) % sizeof(Dst) != 0)) {
			if (__builtin_expect(((src.size() * sizeof(Src)) % sizeof(Dst) != 0), 0)) {
#ifdef KERNEL_PRIVATE
				ml_fatal_trap(0x0800);
#else
				__builtin_verbose_trap("safe-buffers", "reinterpret_span_cast: Conversion between incompatible span sizes");
#endif
			}
		}
	} else {
		static_assert((Count * sizeof(Src)) % sizeof(Dst) == 0,
		    "reinterpret_span_cast: Conversion between incompatible span sizes" );
	}

	using ReturnType = std::span<Dst, Count == std::dynamic_extent
	    ? std::dynamic_extent
	    : (Count * sizeof(Src)) / sizeof(Dst)>;

	return ReturnType {
		       reinterpret_cast<Dst *>(src.data()),
		       (src.size() * sizeof(Src)) / sizeof(Dst)
	};
}

// We keep old function names below for better transitions in Safe
// Buffer adoption.  These names will exist in the header for a while
// before being marked as "deprecated".
namespace span {
template<std::contiguous_iterator It>
std::span<std::remove_reference_t<std::iter_reference_t<It> > >
__unsafe_forge_span(It data, typename std::span<std::remove_reference_t<std::iter_reference_t<It> > >::size_type size)
{
	return std::span<std::remove_reference_t<std::iter_reference_t<It> > >{data, size};
}

template<std::contiguous_iterator It, std::sized_sentinel_for<It> End>
std::span<std::remove_reference_t<std::iter_reference_t<It> > >
__unsafe_forge_span(It begin, End end)
{
	return std::span<std::remove_reference_t<std::iter_reference_t<It> > >{begin, end};
}
} // namespace span
#pragma clang unsafe_buffer_usage end
} // namespace os
#endif /* (defined(__has_include) && __has_include(<span>) && __has_include(<iterator>)) */
#endif /* _OS_CXX_SAFE_BUFFERS_H */
