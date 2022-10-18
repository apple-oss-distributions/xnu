/*
 * Copyright (c) 2000 Apple Inc. All rights reserved.
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
/* OSObject.cpp created by gvdl on Fri 1998-11-17 */

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSLib.h>
#include <libkern/OSDebug.h>
#include <libkern/c++/OSCPPDebug.h>
#include <IOKit/IOKitDebug.h>
#include <libkern/OSAtomic.h>

#include <libkern/c++/OSCollection.h>

#include <kern/queue.h>

__BEGIN_DECLS
size_t debug_ivars_size;
__END_DECLS


// OSDefineMetaClassAndAbstractStructors(OSObject, 0);
/* Class global data */
OSObject::MetaClass OSObject::gMetaClass;
const OSMetaClass * const OSObject::metaClass = &OSObject::gMetaClass;
const OSMetaClass * const OSObject::superClass = NULL;

/* Class member functions - Can't use defaults */
OSObject::~OSObject()
{
}
const OSMetaClass *
OSObject::getMetaClass() const
{
	return &gMetaClass;
}
OSObject *
OSObject::MetaClass::alloc() const
{
	return NULL;
}

/* The OSObject::MetaClass constructor */
OSObject::MetaClass::MetaClass()
	: OSMetaClass("OSObject", OSObject::superClass, sizeof(OSObject))
{
}

// Virtual Padding
OSMetaClassDefineReservedUnused(OSObject, 0);
OSMetaClassDefineReservedUnused(OSObject, 1);
OSMetaClassDefineReservedUnused(OSObject, 2);
OSMetaClassDefineReservedUnused(OSObject, 3);
OSMetaClassDefineReservedUnused(OSObject, 4);
OSMetaClassDefineReservedUnused(OSObject, 5);
OSMetaClassDefineReservedUnused(OSObject, 6);
OSMetaClassDefineReservedUnused(OSObject, 7);
OSMetaClassDefineReservedUnused(OSObject, 8);
OSMetaClassDefineReservedUnused(OSObject, 9);
OSMetaClassDefineReservedUnused(OSObject, 10);
OSMetaClassDefineReservedUnused(OSObject, 11);
OSMetaClassDefineReservedUnused(OSObject, 12);
OSMetaClassDefineReservedUnused(OSObject, 13);
OSMetaClassDefineReservedUnused(OSObject, 14);
OSMetaClassDefineReservedUnused(OSObject, 15);

static const char *
getClassName(const OSObject *obj)
{
	const OSMetaClass *meta = obj->getMetaClass();
	return (meta) ? meta->getClassName() : "unknown class?";
}

int
OSObject::getRetainCount() const
{
	return (int) ((UInt16) retainCount);
}

bool
OSObject::taggedTryRetain(const void *tag) const
{
	volatile UInt32 *countP = (volatile UInt32 *) &retainCount;
	UInt32 inc = 1;
	UInt32 origCount;
	UInt32 newCount;

	// Increment the collection bucket.
	if ((const void *) OSTypeID(OSCollection) == tag) {
		inc |= (1UL << 16);
	}

	do {
		origCount = *countP;
		if (((UInt16) origCount | 0x1) == 0xffff) {
			if (origCount & 0x1) {
				// If count == 0xffff that means we are freeing now so we can
				// just return obviously somebody is cleaning up dangling
				// references.
				return false;
			} else {
				// If count == 0xfffe then we have wrapped our reference count.
				// We should stop counting now as this reference must be
				// leaked rather than accidently wrapping around the clock and
				// freeing a very active object later.

#if !DEBUG
				break; // Break out of update loop which pegs the reference
#else /* DEBUG */
				// @@@ gvdl: eventually need to make this panic optional
				// based on a boot argument i.e. debug= boot flag
				panic("OSObject::refcount: "
				    "About to wrap the reference count, reference leak?");
#endif /* !DEBUG */
			}
		}

		newCount = origCount + inc;
	} while (!OSCompareAndSwap(origCount, newCount, const_cast<UInt32 *>(countP)));

	return true;
}

void
OSObject::taggedRetain(const void *tag) const
{
	if (!taggedTryRetain(tag)) {
		panic("OSObject::refcount: Attempting to retain a freed object");
	}
}

void
OSObject::taggedRelease(const void *tag) const
{
	taggedRelease(tag, 1);
}

void
OSObject::taggedRelease(const void *tag, const int when) const
{
	volatile UInt32 *countP = (volatile UInt32 *) &retainCount;
	UInt32 dec = 1;
	UInt32 origCount;
	UInt32 newCount;
	UInt32 actualCount;

	// Increment the collection bucket.
	if ((const void *) OSTypeID(OSCollection) == tag) {
		dec |= (1UL << 16);
	}

	do {
		origCount = *countP;

		if (((UInt16) origCount | 0x1) == 0xffff) {
			if (origCount & 0x1) {
				// If count == 0xffff that means we are freeing now so we can
				// just return obviously somebody is cleaning up some dangling
				// references.  So we blow out immediately.
				return;
			} else {
				// If count == 0xfffe then we have wrapped our reference
				// count.  We should stop counting now as this reference must be
				// leaked rather than accidently freeing an active object later.

#if !DEBUG
				return; // return out of function which pegs the reference
#else /* DEBUG */
				// @@@ gvdl: eventually need to make this panic optional
				// based on a boot argument i.e. debug= boot flag
				panic("OSObject::refcount: %s",
				    "About to unreference a pegged object, reference leak?");
#endif /* !DEBUG */
			}
		}
		actualCount = origCount - dec;
		if ((UInt16) actualCount < when) {
			newCount = 0xffff;
		} else {
			newCount = actualCount;
		}
	} while (!OSCompareAndSwap(origCount, newCount, const_cast<UInt32 *>(countP)));

	//
	// This panic means that we have just attempted to release an object
	// whose retain count has gone to less than the number of collections
	// it is a member off.  Take a panic immediately.
	// In fact the panic MAY not be a registry corruption but it is
	// ALWAYS the wrong thing to do.  I call it a registry corruption 'cause
	// the registry is the biggest single use of a network of collections.
	//
// xxx - this error message is overly-specific;
// xxx - any code in the kernel could trip this,
// xxx - and it applies as noted to all collections, not just the registry
	if ((UInt16) actualCount < (actualCount >> 16)) {
		panic("A kext releasing a(n) %s has corrupted the registry.",
		    getClassName(this));
	}

	// Check for a 'free' condition and that if we are first through
	if (newCount == 0xffff) {
		(const_cast<OSObject *>(this))->free();
	}
}

void
OSObject::release() const
{
	taggedRelease(NULL);
}

void
OSObject::retain() const
{
	taggedRetain(NULL);
}

extern "C" void
osobject_retain(void * object)
{
	((OSObject *)object)->retain();
}

extern "C" void
osobject_release(void * object)
{
	((OSObject *)object)->release();
}

void
OSObject::release(int when) const
{
	taggedRelease(NULL, when);
}

bool
OSObject::serialize(OSSerialize *s) const
{
	char cstr[128];
	bool ok;

	snprintf(cstr, sizeof(cstr), "%s is not serializable", getClassName(this));

	OSString * str;
	str = OSString::withCStringNoCopy(cstr);
	if (!str) {
		return false;
	}

	ok = str->serialize(s);
	str->release();

	return ok;
}

/*
 * Ignore -Wxnu-typed-allocators for the operator new/delete implementations
 */
__typed_allocators_ignore_push

/*
 * Given that all OSObjects have been transitioned to use
 * OSObject_typed_operator_new/OSObject_typed_operator_delete, this should
 * only be called from kexts that havent recompiled to use the new
 * definitions.
 */
void *
OSObject::operator new(size_t size)
{
#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		return OSMetaClass::trackedNew(size);
	}
#endif

	void *mem = kheap_alloc(KHEAP_DEFAULT, size,
	    Z_VM_TAG_BT(Z_WAITOK_ZERO, VM_KERN_MEMORY_LIBKERN));
	assert(mem);
	OSIVAR_ACCUMSIZE(size);

	return (void *) mem;
}

void *
OSObject_typed_operator_new(kalloc_type_view_t ktv, vm_size_t size)
{
#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		return OSMetaClass::trackedNew(size);
	}
#endif

	/*
	 * Some classes in kexts that subclass from iokit classes
	 * don't use OSDeclare/OSDefine to declare/define structors.
	 * When operator new is called on such objects they end up
	 * using the parent's operator new/delete. If we detect such
	 * a case we default to using kalloc rather than kalloc_type
	 */
	void *mem = NULL;
	if (size <= kalloc_type_get_size(ktv->kt_size)) {
		/*
		 * OSObject_typed_operator_new can be called from kexts,
		 * use the external symbol for kalloc_type_impl as
		 * kalloc_type_views generated at some external callsites
		 * many not have been processed during boot.
		 */
		mem = kalloc_type_impl_external(ktv, Z_WAITOK_ZERO);
	} else {
		mem = kheap_alloc(KHEAP_DEFAULT, size,
		    Z_VM_TAG_BT(Z_WAITOK_ZERO, VM_KERN_MEMORY_LIBKERN));
	}
	assert(mem);
	OSIVAR_ACCUMSIZE(size);

	return (void *) mem;
}

void
OSObject::operator delete(void * mem, size_t size)
{
	if (!mem) {
		return;
	}

#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		return OSMetaClass::trackedDelete(mem, size);
	}
#endif

	kheap_free(KHEAP_DEFAULT, mem, size);
	OSIVAR_ACCUMSIZE(-size);
}

void
OSObject_typed_operator_delete(kalloc_type_view_t ktv, void * mem,
    vm_size_t size)
{
	if (!mem) {
		return;
	}

#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		return OSMetaClass::trackedDelete(mem, size);
	}
#endif

	if (size <= kalloc_type_get_size(ktv->kt_size)) {
		kern_os_typed_free(ktv, mem, size);
	} else {
		kheap_free(KHEAP_DEFAULT, mem, size);
	}
	OSIVAR_ACCUMSIZE(-size);
}

__typed_allocators_ignore_pop

bool
OSObject::init()
{
#if IOTRACKING
	if (kIOTracking & gIOKitDebug) {
		getMetaClass()->trackedInstance(this);
	}
#endif
	return true;
}

void
OSObject::free()
{
	const OSMetaClass *meta = getMetaClass();

	if (meta) {
		meta->instanceDestructed();
#if IOTRACKING
		if (kIOTracking & gIOKitDebug) {
			getMetaClass()->trackedFree(this);
		}
#endif
	}
	delete this;
}

#if IOTRACKING
void
OSObject::trackingAccumSize(size_t size)
{
	if (kIOTracking & gIOKitDebug) {
		getMetaClass()->trackedAccumSize(this, size);
	}
}
#endif

/* Class member functions - Can't use defaults */
/* During constructor vtable is always OSObject's - can't call any subclass */

OSObject::OSObject()
{
	retainCount = 1;
//    if (kIOTracking & gIOKitDebug) getMetaClass()->trackedInstance(this);
}

OSObject::OSObject(const OSMetaClass *)
{
	retainCount = 1;
//    if (kIOTracking & gIOKitDebug) getMetaClass()->trackedInstance(this);
}


bool
OSObject::iterateObjects(void * refcon, bool (*callback)(void * refcon, OSObject * object))
{
	OSCollection * col;
	if ((col = OSDynamicCast(OSCollection, this))) {
		return col->iterateObjects(refcon, callback);
	}
	return callback(refcon, this);
}

bool
OSObject::iterateObjects(bool (^block)(OSObject * object))
{
	OSCollection * col;
	if ((col = OSDynamicCast(OSCollection, this))) {
		return col->iterateObjects(block);
	}
	return block(this);
}
