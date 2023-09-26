/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <mach/exclaves.h>

kern_return_t
exclaves_endpoint_call(mach_port_t port, exclaves_id_t endpoint_id,
    mach_vm_address_t msg_buffer, mach_vm_size_t size, exclaves_tag_t *tag,
    exclaves_error_t *error)
{
#if defined(__LP64__)
	kern_return_t kr = KERN_SUCCESS;
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(ENDPOINT_CALL, 0);
	kr = _exclaves_ctl_trap(port, opf, endpoint_id, msg_buffer, size);
	*tag = 0;
	*error = 0;
	return kr;
#else
#pragma unused(port, endpoint_id, msg_buffer, size, tag, error)
	return KERN_NOT_SUPPORTED;
#endif /* defined(__LP64__) */
}

kern_return_t
exclaves_named_buffer_create(mach_port_t port, exclaves_id_t buffer_id,
    mach_vm_size_t size, mach_port_t* out_named_buffer_port)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_CREATE, 0);
	return _exclaves_ctl_trap(port, opf, buffer_id,
	           (uintptr_t)out_named_buffer_port, size);
}

kern_return_t
exclaves_named_buffer_copyin(mach_port_t named_buffer_port,
    mach_vm_address_t src_buffer, mach_vm_size_t size, mach_vm_size_t offset)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_COPYIN, 0);
	return _exclaves_ctl_trap(named_buffer_port, opf, (exclaves_id_t)offset,
	           src_buffer, size);
}

kern_return_t
exclaves_named_buffer_copyout(mach_port_t named_buffer_port,
    mach_vm_address_t dst_buffer, mach_vm_size_t size, mach_vm_size_t offset)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(NAMED_BUFFER_COPYOUT, 0);
	return _exclaves_ctl_trap(named_buffer_port, opf, (exclaves_id_t)offset,
	           dst_buffer, size);
}

kern_return_t
exclaves_boot(mach_port_t port, uint64_t flags)
{
	const uint32_t opf = EXCLAVES_CTL_OP_AND_FLAGS(BOOT, 0);
	return _exclaves_ctl_trap(port, opf, flags, 0, 0);
}
