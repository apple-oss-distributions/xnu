/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* IOData.m created by rsulack on Thu 25-Sep-1997 */

#include <string.h>

#include <vm/vm_kern.h>

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOLib.h>

#define super OSObject

OSDefineMetaClassAndStructorsWithZone(OSData, OSObject, ZC_ZFREE_CLEARMEM)
OSMetaClassDefineReservedUsedX86(OSData, 0);    // setDeallocFunction
OSMetaClassDefineReservedUnused(OSData, 1);
OSMetaClassDefineReservedUnused(OSData, 2);
OSMetaClassDefineReservedUnused(OSData, 3);
OSMetaClassDefineReservedUnused(OSData, 4);
OSMetaClassDefineReservedUnused(OSData, 5);
OSMetaClassDefineReservedUnused(OSData, 6);
OSMetaClassDefineReservedUnused(OSData, 7);

#define EXTERNAL ((unsigned int) -1)

bool
OSData::initWithCapacity(unsigned int inCapacity)
{
	struct kalloc_result kr;
	bool success = true;

	if (!super::init()) {
		return false;
	}

	/*
	 * OSData use of Z_MAY_COPYINMAP serves 2 purpposes:
	 *
	 * - It makes sure than when it goes to the VM, it uses its own object
	 *   rather than the kernel object so that vm_map_copyin() can be used.
	 *
	 * - On Intel, it goes to the VM for any size >= PAGE_SIZE to maintain
	 *   old (inefficient) ABI. On arm64 it will use kalloc_data() instead
	 *   until the vm_map_copy_t msg_ool_size_small threshold for copies.
	 */

	if (inCapacity == 0) {
		if (capacity) {
			OSCONTAINER_ACCUMSIZE(-(size_t)capacity);
			/* can't use kfree() as we need to pass Z_MAY_COPYINMAP */
			__kheap_realloc(KHEAP_DATA_BUFFERS, data, capacity, 0,
			    Z_VM_TAG_BT(Z_WAITOK_ZERO | Z_MAY_COPYINMAP,
			    VM_KERN_MEMORY_LIBKERN), (void *)&this->data);
			data     = nullptr;
			capacity = 0;
		}
	} else if (inCapacity <= capacity) {
		/*
		 * Nothing to change
		 */
	} else {
		if (inCapacity >= PAGE_SIZE) {
			inCapacity = (uint32_t)round_page(inCapacity);
		}
		kr = kalloc_ext(KHEAP_DATA_BUFFERS, inCapacity,
		    Z_VM_TAG_BT(Z_WAITOK_ZERO | Z_MAY_COPYINMAP,
		    VM_KERN_MEMORY_LIBKERN), (void *)&this->data);

		if (kr.addr) {
			size_t delta = 0;

			data     = kr.addr;
			delta   -= capacity;
			capacity = (uint32_t)MIN(kr.size, UINT32_MAX);
			delta   += capacity;
			OSCONTAINER_ACCUMSIZE(delta);
		} else {
			success = false;
		}
	}

	length = 0;
	capacityIncrement = MAX(16, inCapacity);

	return success;
}

bool
OSData::initWithBytes(const void *bytes, unsigned int inLength)
{
	if ((inLength && !bytes) || !initWithCapacity(inLength)) {
		return false;
	}

	if (bytes != data) {
		bcopy(bytes, data, inLength);
	}
	length = inLength;

	return true;
}

bool
OSData::initWithBytesNoCopy(void *bytes, unsigned int inLength)
{
	if (!super::init()) {
		return false;
	}

	length = inLength;
	capacity = EXTERNAL;
	data = bytes;

	return true;
}

bool
OSData::initWithData(const OSData *inData)
{
	return initWithBytes(inData->data, inData->length);
}

bool
OSData::initWithData(const OSData *inData,
    unsigned int start, unsigned int inLength)
{
	const void *localData = inData->getBytesNoCopy(start, inLength);

	if (localData) {
		return initWithBytes(localData, inLength);
	} else {
		return false;
	}
}

OSSharedPtr<OSData>
OSData::withCapacity(unsigned int inCapacity)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithCapacity(inCapacity)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSData>
OSData::withBytes(const void *bytes, unsigned int inLength)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithBytes(bytes, inLength)) {
		return nullptr;
	}
	return me;
}

OSSharedPtr<OSData>
OSData::withBytesNoCopy(void *bytes, unsigned int inLength)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithBytesNoCopy(bytes, inLength)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSData>
OSData::withData(const OSData *inData)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithData(inData)) {
		return nullptr;
	}

	return me;
}

OSSharedPtr<OSData>
OSData::withData(const OSData *inData,
    unsigned int start, unsigned int inLength)
{
	OSSharedPtr<OSData> me = OSMakeShared<OSData>();

	if (me && !me->initWithData(inData, start, inLength)) {
		return nullptr;
	}

	return me;
}

void
OSData::free()
{
	if ((capacity != EXTERNAL) && data && capacity) {
		/* can't use kfree() as we need to pass Z_MAY_COPYINMAP */
		__kheap_realloc(KHEAP_DATA_BUFFERS, data, capacity, 0,
		    Z_VM_TAG_BT(Z_WAITOK_ZERO | Z_FULLSIZE | Z_MAY_COPYINMAP,
		    VM_KERN_MEMORY_LIBKERN), (void *)&this->data);
		OSCONTAINER_ACCUMSIZE( -((size_t)capacity));
	} else if (capacity == EXTERNAL) {
		DeallocFunction freemem = reserved ? reserved->deallocFunction : NULL;
		if (freemem && data && length) {
			freemem(data, length);
		}
	}
	if (reserved) {
		kfree_type(ExpansionData, reserved);
	}
	super::free();
}

unsigned int
OSData::getLength() const
{
	return length;
}
unsigned int
OSData::getCapacity() const
{
	return capacity;
}

unsigned int
OSData::getCapacityIncrement() const
{
	return capacityIncrement;
}

unsigned int
OSData::setCapacityIncrement(unsigned increment)
{
	return capacityIncrement = increment;
}

// xx-review: does not check for capacity == EXTERNAL

unsigned int
OSData::ensureCapacity(unsigned int newCapacity)
{
	struct kalloc_result kr;
	unsigned int finalCapacity;

	if (newCapacity <= capacity) {
		return capacity;
	}

	finalCapacity = (((newCapacity - 1) / capacityIncrement) + 1)
	    * capacityIncrement;

	// integer overflow check
	if (finalCapacity < newCapacity) {
		return capacity;
	}

	if (finalCapacity >= PAGE_SIZE) {
		finalCapacity = (uint32_t)round_page(finalCapacity);
	}
	kr = krealloc_ext((void *)KHEAP_DATA_BUFFERS, data, capacity, finalCapacity,
	    Z_VM_TAG_BT(Z_WAITOK_ZERO | Z_MAY_COPYINMAP,
	    VM_KERN_MEMORY_LIBKERN), (void *)&this->data);

	if (kr.addr) {
		size_t delta = 0;

		data     = kr.addr;
		delta   -= capacity;
		capacity = (uint32_t)MIN(kr.size, UINT32_MAX);
		delta   += capacity;
		OSCONTAINER_ACCUMSIZE(delta);
	}

	return capacity;
}

bool
OSData::clipForCopyout()
{
	unsigned int newCapacity = (uint32_t)round_page(length);
	__assert_only struct kalloc_result kr;

	/*
	 * OSData allocations are atomic, which means that if copyoutkdata()
	 * is used on them, and that there are fully unused pages at the end
	 * of the OSData buffer, then vm_map_copyin() will try to clip the VM
	 * entry which will panic.
	 *
	 * In order to avoid this, trim down the unused pages.
	 *
	 * We know this operation never fails and keeps the allocation
	 * address stable.
	 */
	if (length >= msg_ool_size_small && newCapacity < capacity) {
		kr = krealloc_ext((void *)KHEAP_DATA_BUFFERS,
		    data, capacity, newCapacity,
		    Z_VM_TAG_BT(Z_WAITOK_ZERO | Z_FULLSIZE | Z_MAY_COPYINMAP,
		    VM_KERN_MEMORY_LIBKERN), (void *)&this->data);
		assert(kr.addr == data);
		OSCONTAINER_ACCUMSIZE(((size_t)newCapacity) - ((size_t)capacity));
		capacity = newCapacity;
	}
	return true;
}

bool
OSData::appendBytes(const void *bytes, unsigned int inLength)
{
	unsigned int newSize;

	if (!inLength) {
		return true;
	}

	if (capacity == EXTERNAL) {
		return false;
	}

	if (os_add_overflow(length, inLength, &newSize)) {
		return false;
	}

	if ((newSize > capacity) && newSize > ensureCapacity(newSize)) {
		return false;
	}

	if (bytes) {
		bcopy(bytes, &((unsigned char *)data)[length], inLength);
	} else {
		bzero(&((unsigned char *)data)[length], inLength);
	}

	length = newSize;

	return true;
}

bool
OSData::appendByte(unsigned char byte, unsigned int inLength)
{
	unsigned int newSize;

	if (!inLength) {
		return true;
	}

	if (capacity == EXTERNAL) {
		return false;
	}

	if (os_add_overflow(length, inLength, &newSize)) {
		return false;
	}

	if ((newSize > capacity) && newSize > ensureCapacity(newSize)) {
		return false;
	}

	memset(&((unsigned char *)data)[length], byte, inLength);
	length = newSize;

	return true;
}

bool
OSData::appendBytes(const OSData *other)
{
	return appendBytes(other->data, other->length);
}

const void *
OSData::getBytesNoCopy() const
{
	if (!length) {
		return NULL;
	} else {
		return data;
	}
}

const void *
OSData::getBytesNoCopy(unsigned int start,
    unsigned int inLength) const
{
	const void *outData = NULL;

	if (length
	    && start < length
	    && (start + inLength) >= inLength // overflow check
	    && (start + inLength) <= length) {
		outData = (const void *) ((char *) data + start);
	}

	return outData;
}

bool
OSData::isEqualTo(const OSData *aData) const
{
	unsigned int len;

	len = aData->length;
	if (length != len) {
		return false;
	}

	return isEqualTo(aData->data, len);
}

bool
OSData::isEqualTo(const void *someData, unsigned int inLength) const
{
	return (length >= inLength) && (bcmp(data, someData, inLength) == 0);
}

bool
OSData::isEqualTo(const OSMetaClassBase *obj) const
{
	OSData *    otherData;
	OSString *  str;

	if ((otherData = OSDynamicCast(OSData, obj))) {
		return isEqualTo(otherData);
	} else if ((str = OSDynamicCast(OSString, obj))) {
		return isEqualTo(str);
	} else {
		return false;
	}
}

bool
OSData::isEqualTo(const OSString *obj) const
{
	const char * aCString;
	char * dataPtr;
	unsigned int checkLen = length;
	unsigned int stringLen;

	if (!obj) {
		return false;
	}

	stringLen = obj->getLength();

	dataPtr = (char *)data;

	if (stringLen != checkLen) {
		// check for the fact that OSData may be a buffer that
		// that includes a termination byte and will thus have
		// a length of the actual string length PLUS 1. In this
		// case we verify that the additional byte is a terminator
		// and if so count the two lengths as being the same.

		if ((checkLen - stringLen) == 1) {
			if (dataPtr[checkLen - 1] != 0) { // non-zero means not a terminator and thus not likely the same
				return false;
			}
			checkLen--;
		} else {
			return false;
		}
	}

	aCString = obj->getCStringNoCopy();

	for (unsigned int i = 0; i < checkLen; i++) {
		if (*dataPtr++ != aCString[i]) {
			return false;
		}
	}

	return true;
}

//this was taken from CFPropertyList.c
static const char __CFPLDataEncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool
OSData::serialize(OSSerialize *s) const
{
	unsigned int i;
	const unsigned char *p;
	unsigned char c;
	unsigned int serializeLength;

	if (s->previouslySerialized(this)) {
		return true;
	}

	if (!s->addXMLStartTag(this, "data")) {
		return false;
	}

	serializeLength = length;
	if (reserved && reserved->disableSerialization) {
		serializeLength = 0;
	}

	for (i = 0, p = (unsigned char *)data; i < serializeLength; i++, p++) {
		/* 3 bytes are encoded as 4 */
		switch (i % 3) {
		case 0:
			c = __CFPLDataEncodeTable[((p[0] >> 2) & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			break;
		case 1:
			c = __CFPLDataEncodeTable[((((p[-1] << 8) | p[0]) >> 4) & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			break;
		case 2:
			c = __CFPLDataEncodeTable[((((p[-1] << 8) | p[0]) >> 6) & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			c = __CFPLDataEncodeTable[(p[0] & 0x3f)];
			if (!s->addChar(c)) {
				return false;
			}
			break;
		}
	}
	switch (i % 3) {
	case 0:
		break;
	case 1:
		c = __CFPLDataEncodeTable[((p[-1] << 4) & 0x30)];
		if (!s->addChar(c)) {
			return false;
		}
		if (!s->addChar('=')) {
			return false;
		}
		if (!s->addChar('=')) {
			return false;
		}
		break;
	case 2:
		c = __CFPLDataEncodeTable[((p[-1] << 2) & 0x3c)];
		if (!s->addChar(c)) {
			return false;
		}
		if (!s->addChar('=')) {
			return false;
		}
		break;
	}

	return s->addXMLEndTag("data");
}

void
OSData::setDeallocFunction(DeallocFunction func)
{
	if (!reserved) {
		reserved = (typeof(reserved))kalloc_type(ExpansionData, (zalloc_flags_t)(Z_WAITOK | Z_ZERO));
		if (!reserved) {
			return;
		}
	}
	reserved->deallocFunction = func;
}

void
OSData::setSerializable(bool serializable)
{
	if (!reserved) {
		reserved = (typeof(reserved))kalloc_type(ExpansionData, (zalloc_flags_t)(Z_WAITOK | Z_ZERO));
		if (!reserved) {
			return;
		}
	}
	reserved->disableSerialization = (!serializable);
}

bool
OSData::isSerializable(void)
{
	return !reserved || !reserved->disableSerialization;
}
