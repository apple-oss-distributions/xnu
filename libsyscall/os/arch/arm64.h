/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#ifndef OS_ARCH_ARM64_H
#define OS_ARCH_ARM64_H

#if defined(__arm64__)

#include <stdbool.h>

#include <sys/cdefs.h>

#include <os/availability.h>

__BEGIN_DECLS

/*!
 * @function os_set_custom_x18_abi_enabled
 *
 * @abstract
 *
 * Switch thread into or out of custom ABI usage for the x18 register.
 *
 * This API comes with lots of caveats. Users of this API must take a
 * disproportionate amount of care, so it is strongly advised to only
 * use this API if absolutely required.
 *
 * Under normal operation, x18 is reserved for operating system usage,
 * and may therefore not be touched by any application code. The Apple
 * ARM64 Application Binary Interface codifies this by stating: "The
 * platforms reserve register x18. Don’t use this register."
 *
 * However, there are special situations, such as when implementing
 * compatibility layers for other ABIs, where custom usage x18 becomes
 * a necessity, notably when it is part of the ABI contract itself
 * (for example, used as a TSD base).
 *
 * This API enables per-thread use of x18 under such special
 * circumstances. To use it, application code must issue
 * `os_set_custom_x18_abi_enabled(true)` at the boundary between the
 * regular macOS application code and the code using the custom
 * ABI. When in this mode, x18 behaves like any other general purpose
 * register for this thread: It has no other semantics towards the
 * operating system other than holding arbitrary values, and it will
 * get saved and restored across context switches like any other
 * GPR. When switching back from the custom ABI code to macOS
 * application code, `os_set_custom_x18_abi_enabled(false)` must then
 * be issued, in order to restore the proper system-defined operating
 * semantics for x18 again.
 *
 * Note that code running after `os_set_custom_x18_abi_enabled(true)`
 * must not call, directly or in the form of callbacks, into any macOS
 * library/framework code in the current thread, with the exception of
 * `os_set_custom_x18_abi_enabled()` and `os_custom_x18_abi_enabled()`
 * themselves.
 *
 * This function strictly toggles the state: calling it with the same
 * value as the current state will cause the process to abort.
 *
 * Great care must also be taken with signal handlers and other
 * asynchronous code entry points. These should either not call into
 * any macOS library/framework code (note that this includes POSIX
 * interfaces), or bracket such calls between
 * `os_set_custom_x18_abi_enabled(false)` and
 * `os_set_custom_x18_abi_enabled(true)`, iff the custom x18 ABI is
 * enabled according to `os_custom_x18_abi_enabled()`.  Any other
 * regular limitations for signal handler code calling into OS
 * functions apply as well. Unless the use of signals is absolutely
 * required, masking all signals before entering custom x18 ABI mode
 * avoids any complication with signal handlers.
 *
 * Also note that the operating system does not preserve any x18 value
 * from within the custom ABI code across
 * `os_set_custom_x18_abi_enabled()` calls. Effectively, calling
 * `os_set_custom_x18_abi_enabled(false)` destroys x18's value. In the
 * likely case that the application code wishes to preserve x18's
 * content for the custom ABI code, the application code must save and
 * restore the affected thread's x18 value itself.
 *
 * `os_set_custom_x18_abi_enabled()` will, however, properly save and
 * restore x18 for its system-defined operating semantics, meaning
 * that application code must not restore x18 in the other direction,
 * i.e. after switching back from custom ABI code to macOS code, nor
 * does it have to save the value before entering custom ABI code (the
 * application code may actually not have the proper information to do
 * so safely). In summary, application code is in charge of x18's
 * value on the "custom ABI side", while macOS itself is in charge of
 * the value on the "macOS side".
 *
 * @param custom true to switch the thread into custom ABI x18 usage,
 * false to switch back to regular macOS x18 semantics.
 *
 */

API_UNAVAILABLE(ios, tvos, watchos, bridgeos) API_AVAILABLE(macos(26.4))
extern
void os_set_custom_x18_abi_enabled(bool custom);

/*!
 * @function os_custom_x18_abi_enabled
 *
 * @abstract
 *
 * Returns whether custom x18 ABI mode is enabled.
 *
 * This can be used to determine if the custom x18 ABI needs temporary
 * disablement prior to calling into any macOS code, e.g. in signal
 * handlers.
 *
 * @return `true` iff custom x18 ABI is enabled.
 */
API_UNAVAILABLE(ios, tvos, watchos, bridgeos) API_AVAILABLE(macos(26.4))
extern
bool os_custom_x18_abi_enabled(void);

__END_DECLS

#endif // defined(__arm64__)

#endif // OS_ARCH_ARM64_H
