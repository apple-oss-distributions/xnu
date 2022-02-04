/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#define IOKIT_ENABLE_SHARED_PTR
#include <IOKit/IOGuardPageMemoryDescriptor.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <vm/vm_kern.h>
#include <mach/mach_vm.h>

#define super IOGeneralMemoryDescriptor

OSDefineMetaClassAndStructorsWithZone(IOGuardPageMemoryDescriptor, IOGeneralMemoryDescriptor, ZC_ZFREE_CLEARMEM);

OSSharedPtr<IOGuardPageMemoryDescriptor>
IOGuardPageMemoryDescriptor::withSize(vm_size_t size)
{
	OSSharedPtr<IOGuardPageMemoryDescriptor> me = OSMakeShared<IOGuardPageMemoryDescriptor>();

	if (me && !me->initWithSize(size)) {
		me.reset();
	}
	return me;
}

bool
IOGuardPageMemoryDescriptor::initWithSize(vm_size_t size)
{
	vm_offset_t address;
	kern_return_t kr;
	IOOptionBits  iomdOptions = kIOMemoryTypeVirtual64 | kIOMemoryAsReference | kIODirectionOutIn;

	size = round_page(size);

	_ranges.v64 = IOMallocType(IOAddressRange);
	if (!_ranges.v64) {
		return false;
	}

	kr = vm_allocate_kernel(kernel_map, &address, size, VM_FLAGS_ANYWHERE, VM_KERN_MEMORY_IOKIT);
	if (kr != KERN_SUCCESS) {
		return false;
	}


	_ranges.v64->address = (mach_vm_address_t) address;
	_ranges.v64->length  = size;

	if (!super::initWithOptions(_ranges.v64, 1, 0, kernel_task, iomdOptions, NULL)) {
		return false;
	}

	_size = size;
	_buffer = address;

	return true;
}

void
IOGuardPageMemoryDescriptor::free()
{
	IOAddressRange * range = _ranges.v64;

	if (_buffer) {
		vm_deallocate(kernel_map, _buffer, _size);
	}

	if (range) {
		IOFreeType(range, IOAddressRange);
	}

	super::free();
}

IOReturn
IOGuardPageMemoryDescriptor::doMap(vm_map_t           addressMap,
    IOVirtualAddress * atAddress,
    IOOptionBits       options,
    IOByteCount        sourceOffset,
    IOByteCount        length)
{
	IOReturn ret = super::doMap(addressMap, atAddress, options, sourceOffset, length);
	if (ret == kIOReturnSuccess) {
		IOMemoryMap *     mapping = (IOMemoryMap *) *atAddress;
		vm_map_t          map     = mapping->fAddressMap;
		mach_vm_size_t    length  = mapping->fLength;
		mach_vm_address_t address = mapping->fAddress;
		kern_return_t kr = mach_vm_protect(map, address, length, true, VM_PROT_NONE);
		if (kr != KERN_SUCCESS) {
			doUnmap(map, (IOVirtualAddress) mapping, 0);
			return kIOReturnError;
		}
	}
	return ret;
}
