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

#if (defined(__has_include) && __has_include(<span>))
#include <span>

namespace os {
namespace span {
#pragma clang unsafe_buffer_usage begin
/* The `__unsafe_forge_span` functions are for suppressing false
 *  positive `-Wunsafe-buffer-usage-in-container` warnings on
 *  uses of the two-parameter `std::span` constructors.
 *
 *  For a `std::span(ptr, size)` call that raises a false alarm, one
 *  can suppress the warning by changing the call to
 *  `__unsafe_forge_span(ptr, size)`.
 *
 *  Please consider the C++ Safe Buffers Programming Model and
 *  Adoption Tooling Guide as a reference to identify false positives
 *  and do not use the functions in non-applicable cases.
 */
template<class It>
std::span<std::remove_reference_t<std::iter_reference_t<It> > >
__unsafe_forge_span(It data, typename std::span<std::remove_reference_t<std::iter_reference_t<It> > >::size_type size)
{
	return std::span<std::remove_reference_t<std::iter_reference_t<It> > >
	       {data, size};
}

template<std::contiguous_iterator It, std::sized_sentinel_for<It> End>
std::span<std::remove_reference_t<std::iter_reference_t<It> > >
__unsafe_forge_span(It begin, End end)
{
	return std::span<std::remove_reference_t<std::iter_reference_t<It> > >{begin, end};
}
#pragma clang unsafe_buffer_usage end
} // namespace span
} // namespace os
#endif /* (defined(__has_include) && __has_include(<span>)) */
#endif /* _OS_CXX_SAFE_BUFFERS_H */
