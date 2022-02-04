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
/* IOArray.h created by rsulack on Thu 11-Sep-1997 */

#define IOKIT_ENABLE_SHARED_PTR

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSCollection.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSSharedPtr.h>

#define super OSIterator

OSDefineMetaClassAndStructors(OSCollectionIterator, OSIterator)

bool
OSCollectionIterator::initWithCollection(const OSCollection *inColl)
{
	if (!super::init() || !inColl) {
		return false;
	}

	collection.reset(inColl, OSRetain);
	collIterator = NULL;
	initialUpdateStamp = 0;
	valid = false;

	return true;
}

OSSharedPtr<OSCollectionIterator>
OSCollectionIterator::withCollection(const OSCollection *inColl)
{
	OSSharedPtr<OSCollectionIterator> me = OSMakeShared<OSCollectionIterator>();

	if (me && !me->initWithCollection(inColl)) {
		return nullptr;
	}

	return me;
}

void
OSCollectionIterator::free()
{
	freeIteratorStorage();

	collection.reset();

	super::free();
}

void
OSCollectionIterator::reset()
{
	valid = false;
	bool initialized = initializeIteratorStorage();

	if (!initialized) {
		// reusing existing storage
		void * storage = getIteratorStorage();
		bzero(storage, collection->iteratorSize());

		if (!collection->initIterator(storage)) {
			return;
		}

		initialUpdateStamp = collection->updateStamp;
		valid = true;
	}
}

bool
OSCollectionIterator::isValid()
{
	initializeIteratorStorage();

	if (!valid || collection->updateStamp != initialUpdateStamp) {
		return false;
	}

	return true;
}

bool
OSCollectionIterator::initializeIteratorStorage()
{
	void * result = NULL;
	bool initialized = false;

#if __LP64__
	OSCollectionIteratorStorageType storageType = getStorageType();
	switch (storageType) {
	case OSCollectionIteratorStorageUnallocated:
		if (collection->iteratorSize() > sizeof(inlineStorage) || isSubclassed()) {
			collIterator = (void *)kalloc_data(collection->iteratorSize(), Z_WAITOK);
			OSCONTAINER_ACCUMSIZE(collection->iteratorSize());
			if (!collection->initIterator(collIterator)) {
				kfree_data(collIterator, collection->iteratorSize());
				OSCONTAINER_ACCUMSIZE(-((size_t) collection->iteratorSize()));
				collIterator = NULL;
				initialized = false;
				setStorageType(OSCollectionIteratorStorageUnallocated);
			} else {
				setStorageType(OSCollectionIteratorStoragePointer);
				result = collIterator;
				initialized = true;
			}
		} else {
			bzero(&inlineStorage[0], collection->iteratorSize());
			if (!collection->initIterator(&inlineStorage[0])) {
				bzero(&inlineStorage[0], collection->iteratorSize());
				initialized = false;
				setStorageType(OSCollectionIteratorStorageUnallocated);
			} else {
				setStorageType(OSCollectionIteratorStorageInline);
				result = &inlineStorage[0];
				initialized = true;
			}
		}
		break;
	case OSCollectionIteratorStoragePointer:
		// already initialized
		initialized = false;
		break;
	case OSCollectionIteratorStorageInline:
		// already initialized
		initialized = false;
		break;
	default:
		panic("unexpected storage type %u", storageType);
	}
#else
	if (!collIterator) {
		collIterator = (void *)kalloc_data(collection->iteratorSize(), Z_WAITOK);
		OSCONTAINER_ACCUMSIZE(collection->iteratorSize());
		if (!collection->initIterator(collIterator)) {
			kfree_data(collIterator, collection->iteratorSize());
			OSCONTAINER_ACCUMSIZE(-((size_t) collection->iteratorSize()));
			collIterator = NULL;
			initialized = false;
			setStorageType(OSCollectionIteratorStorageUnallocated);
		} else {
			setStorageType(OSCollectionIteratorStoragePointer);
			result = collIterator;
			initialized = true;
		}
	}
#endif /* __LP64__ */

	if (initialized) {
		valid = true;
		initialUpdateStamp = collection->updateStamp;
	}

	return initialized;
}

void *
OSCollectionIterator::getIteratorStorage()
{
	void * result = NULL;

#if __LP64__
	OSCollectionIteratorStorageType storageType = getStorageType();

	switch (storageType) {
	case OSCollectionIteratorStorageUnallocated:
		result = NULL;
		break;
	case OSCollectionIteratorStoragePointer:
		result = collIterator;
		break;
	case OSCollectionIteratorStorageInline:
		result = &inlineStorage[0];
		break;
	default:
		panic("unexpected storage type %u", storageType);
	}
#else
	OSCollectionIteratorStorageType storageType __assert_only = getStorageType();
	assert(storageType == OSCollectionIteratorStoragePointer || storageType == OSCollectionIteratorStorageUnallocated);
	result = collIterator;
#endif /* __LP64__ */

	return result;
}

void
OSCollectionIterator::freeIteratorStorage()
{
#if __LP64__
	OSCollectionIteratorStorageType storageType = getStorageType();

	switch (storageType) {
	case OSCollectionIteratorStorageUnallocated:
		break;
	case OSCollectionIteratorStoragePointer:
		kfree_data(collIterator, collection->iteratorSize());
		OSCONTAINER_ACCUMSIZE(-((size_t) collection->iteratorSize()));
		collIterator = NULL;
		setStorageType(OSCollectionIteratorStorageUnallocated);
		break;
	case OSCollectionIteratorStorageInline:
		bzero(&inlineStorage[0], collection->iteratorSize());
		setStorageType(OSCollectionIteratorStorageUnallocated);
		break;
	default:
		panic("unexpected storage type %u", storageType);
	}
#else
	if (collIterator != NULL) {
		assert(getStorageType() == OSCollectionIteratorStoragePointer);
		kfree_data(collIterator, collection->iteratorSize());
		OSCONTAINER_ACCUMSIZE(-((size_t) collection->iteratorSize()));
		collIterator = NULL;
		setStorageType(OSCollectionIteratorStorageUnallocated);
	} else {
		assert(getStorageType() == OSCollectionIteratorStorageUnallocated);
	}
#endif /* __LP64__ */
}

bool
OSCollectionIterator::isSubclassed()
{
	return getMetaClass() != OSCollectionIterator::metaClass;
}

OSCollectionIteratorStorageType
OSCollectionIterator::getStorageType()
{
#if __LP64__
	// Storage type is in the most significant 2 bits of collIterator
	return (OSCollectionIteratorStorageType)((uintptr_t)(collIterator) >> 62);
#else
	if (collIterator != NULL) {
		return OSCollectionIteratorStoragePointer;
	} else {
		return OSCollectionIteratorStorageUnallocated;
	}
#endif /* __LP64__ */
}

void
OSCollectionIterator::setStorageType(OSCollectionIteratorStorageType storageType)
{
#if __LP64__
	switch (storageType) {
	case OSCollectionIteratorStorageUnallocated:
		if (collIterator != NULL) {
			assert(getStorageType() == OSCollectionIteratorStorageInline);
			collIterator = NULL;
		}
		break;
	case OSCollectionIteratorStoragePointer:
		// Should already be set
		assert(collIterator != NULL);
		assert(getStorageType() == OSCollectionIteratorStoragePointer);
		break;
	case OSCollectionIteratorStorageInline:
		// Set the two most sigificant bits of collIterator to 10b
		collIterator = (void *)(((uintptr_t)collIterator & ~0xC000000000000000) | ((uintptr_t)OSCollectionIteratorStorageInline << 62));
		break;
	default:
		panic("unexpected storage type %u", storageType);
	}
#else
	switch (storageType) {
	case OSCollectionIteratorStorageUnallocated:
		// Should already be set
		assert(collIterator == NULL);
		assert(getStorageType() == OSCollectionIteratorStorageUnallocated);
		break;
	case OSCollectionIteratorStoragePointer:
		// Should already be set
		assert(collIterator != NULL);
		assert(getStorageType() == OSCollectionIteratorStoragePointer);
		break;
	case OSCollectionIteratorStorageInline:
		panic("cannot use inline storage on LP32");
		break;
	default:
		panic("unexpected storage type %u", storageType);
	}
#endif /* __LP64__ */
}

OSObject *
OSCollectionIterator::getNextObject()
{
	OSObject *retObj;
	bool retVal;
	void * storage;

	if (!isValid()) {
		return NULL;
	}

	storage = getIteratorStorage();
	assert(storage != NULL);

	retVal = collection->getNextObjectForIterator(storage, &retObj);
	return (retVal)? retObj : NULL;
}
