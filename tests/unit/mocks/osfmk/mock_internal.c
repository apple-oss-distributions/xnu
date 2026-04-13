/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include "mock_internal.h"
#include "mocks/mock_dynamic.h"
#include "mocks/std_safe.h"
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/dt_proxy.h"

#include "mocks/osfmk/fibers/random.h"

#include <kern/assert.h>
#include <kern/btlog.h>
#include <mach/arm/vm_types.h> // for vm_offset_t
#include <mach/memory_object_types.h>
#include <mach/vm_behavior.h>
#include <mach/vm_inherit.h>
#include <mach/vm_types.h>
#include <mach/vm_types_unsafe.h>
#include <vm/vm_sanitize_telemetry.h>

/*
 * This file contains mocks that are required for XNU bootstrapping, threading functionality,
 * and for testing the mock infrastructure itself.
 * Do not add here mocks that are not related to these functions.
 */

// This initialized the darwintest asserts proxies in the mocks .dylib
struct dt_proxy_callbacks *dt_proxy = NULL;
void
set_dt_proxy_mock(struct dt_proxy_callbacks *p)
{
	dt_proxy = p;
}
struct dt_proxy_callbacks *
get_dt_proxy_mock(void)
{
	return dt_proxy;
}

T_MOCK_F(vm_offset_t,
min_valid_stack_address, (void), ())
{
	return 0;
}

T_MOCK_F(vm_offset_t,
max_valid_stack_address, (void), ())
{
	return 0;
}

T_MOCK_F(u_int32_t,
RandomULong, (void), ())
{
	return (u_int32_t)random_next();
}

T_MOCK_F(uint64_t,
early_random, (void), ())
{
	return random_next();
}

// needed because in-kernel impl for some reason got to libcorecrypt dyld
T_MOCK_F(void,
read_erandom, (void * buffer, unsigned int numBytes), (buffer, numBytes))
{
	unsigned char *cbuf = (unsigned char *)buffer;
	for (int i = 0; i < numBytes; ++i) {
		cbuf[i] = (unsigned char)(random_next() % 0xFF);
	}
}

T_MOCK_F(void,
read_random, (void * buffer, unsigned int numbytes), (buffer, numbytes))
{
	read_erandom(buffer, numbytes);
}

T_MOCK_F(uint32_t,
PE_get_random_seed, (unsigned char *dst_random_seed, uint32_t request_size), (dst_random_seed, request_size))
{
	for (uint32_t i = 0; i < request_size; i++, dst_random_seed++) {
		*dst_random_seed = 0;
	}
	return request_size;
}

T_MOCK_F(bool,
ml_unsafe_kernel_text, (void), ())
{
	return true;
}



T_MOCK_F(void,
os_log_with_args, (
	void* oslog,
	uint8_t type,
	const char *fmt,
	va_list args,
	void *addr), (oslog, type, fmt, args, addr))
{
	char buf[PRINT_BUF_SIZE];
	int printed = vsnprintf(buf, PRINT_BUF_SIZE, fmt, args);
	if (printed > PRINT_BUF_SIZE - 1) {
		printed = PRINT_BUF_SIZE - 1;
	}
#if 0  // this can be switched on if we want pre-main logs
	buf[printed] = '\n';
	write(STDOUT_FILENO, buf, printed);
#else
	PT_LOG(buf);
#endif
}


// The panic() mock works in conjunction with T_ASSERT_PANIC()
// XNU code that panics doesn't expect panic() to return so any function that calls panic() doesn't bother
// to return gracefully to its caller with an error.
// In a unit-test we still want to call a function that is expected to panic, and then be able to run code after it.
// T_ASSERT_PANIC creates a setjmp() point before the call that is expected to panic.
// Once the panic callback panic_trap_to_debugger() is called it does a longjmp() to that jump point.
// This has a similar effect as C++ exceptions, except that any memory allocations performed by the code
// prior to the panic are going to be leaked.

T_MOCK_F(void,
panic_trap_to_debugger, (
	const char *panic_format_str,
	va_list * panic_args,
	unsigned int reason,
	void *ctx,
	uint64_t panic_options_mask,
	void *panic_data,
	unsigned long panic_caller,
	const char *panic_initiator),
(panic_format_str, panic_args, reason, ctx, panic_options_mask, panic_data, panic_caller, panic_initiator))
{
	char buf[PRINT_BUF_SIZE];
	vsnprintf(buf, PRINT_BUF_SIZE, panic_format_str, *panic_args);
	PT_LOG_OR_RAW_FMTSTR("panic! %s", buf);
	ut_check_expected_panic(buf); // may not return
	PT_FAIL("☠️  Panic was unexpected, exiting");
	print_current_backtrace();
	abort();
}

T_MOCK_F(void,
vm_sanitize_send_telemetry, (
	vm_sanitize_method_t method,
	vm_sanitize_checker_t checker,
	vm_sanitize_checker_count_t checker_count,
	enum vm_sanitize_subsys_error_codes ktriage_code,
	uint64_t arg1,
	uint64_t arg2,
	uint64_t arg3,
	uint64_t arg4,
	uint64_t future_ret,
	uint64_t past_ret), (method, checker, checker_count, ktriage_code, arg1, arg2, arg3, arg4, future_ret, past_ret))
{
}

#if (DEBUG || DEVELOPMENT)

T_MOCK_F(vm_size_t,
zone_element_info, (
	void *addr,
	vm_tag_t * ptag), (addr, ptag))
{
	return 0;
}

#endif // DEBUG || DEVELOPMENT

// added for setup_nested_submap()
T_MOCK_F(kern_return_t,
csm_setup_nested_address_space, (
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size), (pmap, region_addr, region_size))
{
	return KERN_SUCCESS;
}

T_MOCK_F(kern_return_t,
csm_associate_debug_region, (
	pmap_t monitor_pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size), (monitor_pmap, region_addr, region_size))
{
	return KERN_SUCCESS;
}

T_MOCK_F(btref_t,
btref_get, (
	void *fp,
	btref_get_flags_t flags), (fp, flags))
{
	return 0;
}

T_MOCK(vm_offset_t, ml_io_map_wcomb, (vm_offset_t phys_addr, vm_size_t size), (phys_addr, size));

T_MOCK_F(unsigned int,
ml_get_cpu_number_local, (void), ())
{
	return 0;
}

T_MOCK_F(int,
get_system_inshutdown, (void), ())
{
	return false;
}

T_MOCK(
	void,
	bzero_phys,
	(addr64_t src, vm_size_t bytes),
	(src, bytes));

T_MOCK(
	bool,
	developer_mode_state,
	(void),
	());

T_MOCK(
	bool,
	csm_enabled,
	(void),
	());

T_MOCK(char *, PE_boot_args, (void), ());

#ifdef copyin
#undef copyin
#endif
#ifdef copyout
#undef copyout
#endif

T_MOCK_F(int,
copyin, (const user_addr_t uaddr, void *kaddr, size_t len), (uaddr, kaddr, len))
{
	// uaddr is an invalid address, an offset in the vm
	// memcpy(kaddr, (const void *)uaddr, len);
	return 0;
}

T_MOCK_F(int,
copyout, (const void *kaddr, user_addr_t udaddr, size_t len), (kaddr, udaddr, len))
{
	// uaddr is an invalid address, an offset in the vm
	// memcpy((void *)udaddr, kaddr, len);
	return 0;
}

#if (DEBUG || DEVELOPMENT)
// these are used for testing the mocking framework, xnu has them only in development || debug
T_MOCK_F(size_t, kernel_func1, (int a, char b), (a, b)) { return 0; };
T_MOCK_F(size_t, kernel_func2, (int a, char b), (a, b)) { return 0; };
T_MOCK_F(size_t, kernel_func3, (int a, char b), (a, b)) { return 0; };
T_MOCK_F(size_t, kernel_func4, (int a, char b), (a, b)) { return 0; };
T_MOCK_F(size_t, kernel_func5, (int a, char b), (a, b)) { return kernel_func5(a, b); };
T_MOCK_F(void, kernel_func6, (int a, char b), (a, b)) { kernel_func6(a, b); };
T_MOCK(size_t, kernel_func7, (int a, char b), (a, b));
T_MOCK(void, kernel_func8, (int a, char b), (a, b));
T_MOCK_F(size_t, kernel_func10, (int a, char b), (a, b)) { return kernel_func10(a, b) + 1000; }

T_MOCK_OVERLOAD(int, kernel_func9, (const char* a))
{
	return 100 + kernel_func9(a);
}
T_MOCK_OVERLOAD(int, kernel_func9, (int a))
{
	return 200 + kernel_func9(a);
}
T_MOCK_OVERLOAD_NOATTR(int, kernel_func9, (int a, int b))
{
	return 300 + kernel_func9(a, b);
}

#endif // DEBUG || DEVELOPMENT
