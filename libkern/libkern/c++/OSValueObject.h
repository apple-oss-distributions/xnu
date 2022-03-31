/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
/* OSValueObject.h created by spoirier on Mon 28-Jun-2021 */

#ifndef _OS_OSVALUEOBJECT_H
#define _OS_OSVALUEOBJECT_H

#if KERNEL_PRIVATE
#if __cplusplus >= 201703L /* C++17 is required for this class */

#include <IOKit/IOLib.h>
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSPtr.h>
#include <os/base.h>
#include <string.h>

/*!
 * @header
 *
 * @abstract
 * This header declares the OSValueObject container class.
 */


namespace os_detail {
kalloc_type_view_t GetOSValueObjectKTV();
}

/*!
 * @class OSValueObject
 *
 * @abstract
 * OSValueObject wraps a single C++ type allocation in a C++ object
 * for use in Libkern collections.
 *
 * @discussion
 * OSValueObject a single type heap allocated as a Libkern C++ object.
 * OSValueObject objects are mutable:
 * You can overwrite the value data it contains.
 *
 * <b>Use Restrictions</b>
 *
 * With very few exceptions in the I/O Kit, all Libkern-based C++
 * classes, functions, and macros are <b>unsafe</b>
 * to use in a primary interrupt context.
 * Consult the I/O Kit documentation related to primary interrupts
 * for more information.
 *
 * OSValueObject provides no concurrency protection;
 * it's up to the usage context to provide any protection necessary.
 * Some portions of the I/O Kit, such as
 * @link //apple_ref/doc/class/IORegistryEntry IORegistryEntry@/link,
 * handle synchronization via defined member functions for setting
 * properties.
 */
template <typename T>
class OSValueObject final : public OSObject
{
public:

/*!
 * @function create
 *
 * @abstract
 * Creates and initializes an empty instance of OSValueObject,
 * where the contained object's memory has been zeroed and then
 * default-constructed.
 *
 * @result
 * An instance of OSValueObject with a reference count of 1;
 * <code>nullptr</code> on failure.
 */
	static OSPtr<OSValueObject> create();

/*!
 * @function withBytes
 *
 * @abstract
 * Creates and initializes an instance of OSValueObject
 * with a copy of the provided value.
 *
 * @param value    A reference to the value to copy.
 *
 * @result
 * An instance of OSValueObject containing a copy of the provided value,
 * with a reference count of 1;
 * <code>nullptr</code> on failure.
 */
	static OSPtr<OSValueObject> withValue(const T& value);

/*!
 * @function withValueObject
 *
 * @abstract
 * Creates and initializes an instance of OSValueObject
 * with contents copied from another OSValueObject object.
 *
 * @param inValueObject An OSValueObject object that provides the initial data.
 *
 * @result
 * An instance of OSValueObject containing a copy of the data in
 * <code>inValueObject</code>, with a reference count of 1;
 * <code>nullptr</code> on failure.
 */
	static OSPtr<OSValueObject> withValueObject(const OSValueObject * inValueObject);

/*!
 * @function free
 *
 * @abstract
 * Deallocates or releases any resources
 * used by the OSValueObject instance.
 *
 * @discussion
 * This function should not be called directly;
 * use
 * <code>@link
 * //apple_ref/cpp/instm/OSObject/release/virtualvoid/()
 * release@/link</code>
 * instead.
 */
	void free() APPLE_KEXT_OVERRIDE;

/*!
 * @function setValue
 *
 * @abstract
 * Replaces the contents of the OSValueObject object's internal data buffer
 * with a copy of the provided value.
 *
 * @param value    A reference to the value to copy.
 */
	void setValue(const T& value);

/*!
 * @function getBytesNoCopy
 *
 * @abstract
 * Returns a pointer to the OSValueObject object's internal data buffer.
 *
 * @result
 * A pointer to the OSValueObject object's internal data buffer.
 *
 * @discussion
 * You cannot modify the existing contents of an OSValueObject object
 * via this function.
 */
	const T * getBytesNoCopy() const;

/*!
 * @function getMutableBytesNoCopy
 *
 * @abstract
 * Returns a pointer to the OSValueObject object's internal data buffer.
 *
 * @result
 * A pointer to the OSValueObject object's internal data buffer.
 *
 * @discussion
 * You can modify the existing contents of an OSValueObject object
 * via this function.
 */
	T * getMutableBytesNoCopy();

/*!
 * @function getRef
 *
 * @abstract
 * Returns a const reference to the OSValueObject object's internal value data.
 *
 * @result
 * A const reference to the OSValueObject object's internal value data.
 *
 * @discussion
 * You cannot modify the existing contents of an OSValueObject object
 * via this function.
 */
	const T & getRef() const;

/*!
 * @function getMutableRef
 *
 * @abstract
 * Returns a pointer to the OSValueObject object's internal value data.
 *
 * @result
 * A pointer to the OSValueObject object's internal value data.
 *
 * @discussion
 * You can modify the existing contents of an OSValueObject object
 * via this function.
 */
	T & getMutableRef();

/*!
 * @function getLength
 *
 * @abstract
 * Returns the number of bytes in or referenced by the OSValueObject object.
 *
 * @result
 * The number of bytes in or referenced by the OSValueObject object.
 */
	constexpr size_t
	getLength() const
	{
		return sizeof(T);
	}

/*!
 * @function isEqualTo
 *
 * @abstract
 * Tests the equality of two OSValueObject objects.
 *
 * @param inValueObject The OSValueObject object being compared against the receiver.
 *
 * @result
 * <code>true</code> if the two OSValueObject objects are equivalent,
 * <code>false</code> otherwise.
 *
 * @discussion
 * Two OSValueObject objects are considered equal
 * if they have same length and if their
 * byte buffers hold the same contents.
 */
	virtual bool isEqualTo(const OSValueObject * inValueObject) const;


/*!
 * @function isEqualTo
 *
 * @abstract
 * Tests the equality of an OSValueObject object's contents
 * to a C array of bytes.
 *
 * @param value    A reference to the value to compare.
 *
 * @result
 * <code>true</code> if the values' data are equal,
 * <code>false</code> otherwise.
 */
	virtual bool isEqualTo(const T& value) const;


/*!
 * @function isEqualTo
 *
 * @abstract
 * Tests the equality of an OSValueObject object to an arbitrary object.
 *
 * @param inObject The object to be compared against the receiver.
 *
 * @result
 * <code>true</code> if the two objects are equivalent,
 * <code>false</code> otherwise.
 *
 * @discussion
 * An OSValueObject is considered equal to another object
 * if that object is derived from OSValueObject<T>
 * and contains the equivalent bytes of the same length.
 */
	virtual bool isEqualTo(const OSMetaClassBase * inObject) const APPLE_KEXT_OVERRIDE;

/*!
 * @function serialize
 *
 * @abstract
 * This class is not serializable.
 *
 * @param serializer The OSSerialize object.
 *
 * @result
 * <code>false</code> always
 */
	virtual bool serialize(OSSerialize * serializer) const APPLE_KEXT_OVERRIDE;

protected:

/*!
 * @function init
 *
 * @abstract
 * Initializes an instance of OSValueObject with a zeroed
 * and then default-constructed data buffer.
 *
 * @result
 * <code>true</code> on success, <code>false</code> on failure.
 *
 * @discussion
 * Not for general use. Use the static instance creation method
 * <code>@link create create@/link</code> instead.
 */
	virtual bool init() APPLE_KEXT_OVERRIDE;

private:
	T * OS_PTRAUTH_SIGNED_PTR("OSValueObject.data") data = nullptr;


	// inline expansion of OSDeclareDefaultStructors and OSDefineMetaClassAndStructors macros
	// (existing macros do not support template classes)
public:
	OSValueObject() : OSObject(&gMetaClass)
	{
		gMetaClass.instanceConstructed();
	}

	static inline class MetaClass : public OSMetaClass
	{
public:
		MetaClass() : OSMetaClass("OSValueObject", &OSObject::gMetaClass, sizeof(OSValueObject))
		{
		}
		virtual OSObject *
		alloc() const APPLE_KEXT_OVERRIDE
		{
			return new OSValueObject;
		}
	} gMetaClass;
	static inline const OSMetaClass * const metaClass = &OSValueObject::gMetaClass;

	friend class OSValueObject::MetaClass;

	virtual const OSMetaClass *
	getMetaClass() const APPLE_KEXT_OVERRIDE
	{
		return &gMetaClass;
	}

	static void *
	operator new(size_t size)
	{
		// requires alternate implementation if this SPI is ever made public API
		return OSObject_typed_operator_new(os_detail::GetOSValueObjectKTV(), size);
	}

protected:
	explicit OSValueObject(const OSMetaClass * meta) : OSObject(meta)
	{
	}

	static void
	operator delete(void * mem, size_t size)
	{
		// requires alternate implementation if this SPI is ever made public API
		return OSObject_typed_operator_delete(os_detail::GetOSValueObjectKTV(), mem, size);
	}
};

/*!
 * @function OSValueObjectWithValue
 *
 * @abstract
 * Creates and initializes an instance of OSValueObject
 * with a copy of the provided value.
 * This is a free function wrapper of OSValueObject<T>::withValue to allow for
 * type inference of the class' template argument from the function parameter
 * (so that you do not need to explicitly provide the type template argument).
 *
 * @param value    A reference to the value to copy.
 *
 * @result
 * An instance of OSValueObject containing a copy of the provided value,
 * with a reference count of 1;
 * <code>nullptr</code> on failure.
 */
template <typename T>
OSPtr<OSValueObject<T> > OSValueObjectWithValue(const T& value);


#pragma mark -

void* operator new(size_t, void*) noexcept; // forward declaration needed for placement-new

template <typename T>
OSPtr<OSValueObject<T> >
OSValueObject<T>::create()
{
#ifdef IOKIT_ENABLE_SHARED_PTR
	auto me = OSMakeShared<OSValueObject<T> >();
#else
	auto * me = OSTypeAlloc(OSValueObject<T>);
#endif
	if (me && !me->init()) {
#ifndef IOKIT_ENABLE_SHARED_PTR
		me->release();
#endif
		return nullptr;
	}
	return me;
}

template <typename T>
OSPtr<OSValueObject<T> >
OSValueObject<T>::withValue(const T& value)
{
#ifdef IOKIT_ENABLE_SHARED_PTR
	OSSharedPtr<OSValueObject<T> > me = create();
#else
	OSValueObject<T> * me = create();
#endif
	if (me) {
		me->setValue(value);
	}
	return me;
}

template <typename T>
OSPtr<OSValueObject<T> >
OSValueObject<T>::withValueObject(const OSValueObject * inValueObject)
{
	if (!inValueObject || !inValueObject->getBytesNoCopy()) {
		return {};
	}
	return withValue(inValueObject->getRef());
}

template <typename T>
bool
OSValueObject<T>::init()
{
	if (!OSObject::init()) {
		return false;
	}

	if (data) {
		data->~T();
		bzero(data, getLength());
	} else {
		data = IOMallocType(T);
		if (!data) {
			return false;
		}
	}

	::new (static_cast<void*>(data)) T();

	return true;
}

template <typename T>
void
OSValueObject<T>::free()
{
	IOFreeType(data, T);
	data = nullptr;

	OSObject::free();
}

template <typename T>
void
OSValueObject<T>::setValue(const T& value)
{
	//static_assert(__is_trivially_copyable(T) || __is_copy_assignable(T));
	if (&value != data) {
		if constexpr (__is_trivially_copyable(T)) {
			memcpy(data, &value, getLength());
		} else {
			*data = value;
		}
	}
}

template <typename T>
const T *
OSValueObject<T>::getBytesNoCopy() const
{
	return data;
}

template <typename T>
T *
OSValueObject<T>::getMutableBytesNoCopy()
{
	return data;
}

template <typename T>
const T &
OSValueObject<T>::getRef() const
{
	assert(data);
	return *data;
}

template <typename T>
T &
OSValueObject<T>::getMutableRef()
{
	assert(data);
	return *data;
}

template <typename T>
bool
OSValueObject<T>::isEqualTo(const OSValueObject * inValueObject) const
{
	return inValueObject && isEqualTo(inValueObject->getRef());
}

template <typename T>
bool
OSValueObject<T>::isEqualTo(const T& value) const
{
	if constexpr (__is_scalar(T) || __is_aggregate(T)) {
		return memcmp(data, &value, getLength()) == 0;
	} else {
		return *data == value;
	}
}

template <typename T>
bool
OSValueObject<T>::isEqualTo(const OSMetaClassBase * inObject) const
{
	if (const auto * const otherValueObject = OSDynamicCast(OSValueObject, inObject)) {
		return isEqualTo(otherValueObject);
	}
	return false;
}

template <typename T>
bool
OSValueObject<T>::serialize(__unused OSSerialize * serializer) const
{
	return false;
}

template <typename T>
OSPtr<OSValueObject<T> >
OSValueObjectWithValue(const T& value)
{
	return OSValueObject<T>::withValue(value);
}


#endif /* __cplusplus */
#endif /* KERNEL_PRIVATE */

#endif /* !_OS_OSVALUEOBJECT_H */
