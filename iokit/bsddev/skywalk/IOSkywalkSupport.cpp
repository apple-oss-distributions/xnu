/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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
#if defined(__x86_64__)
#include <libkern/c++/OSKext.h> // IOSKCopyKextIdentifierWithAddress()
#endif

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOMultiMemoryDescriptor.h>
#include <IOKit/IOCommand.h>
#include <IOKit/IOLib.h>
#include <IOKit/skywalk/IOSkywalkSupport.h>
#include <skywalk/os_skywalk_private.h>
#include <sys/errno.h>
#include <sys/queue.h>

#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_types.h>

#define ELOG(fmt, args...)      SK_ERR(fmt, ##args)
#define DLOG(fmt, args...)      SK_DF(SK_VERB_IOSK, fmt, ##args)
#define IOSK_SIZE_OK(x)         (((x) != 0) && (round_page(x) == (x)))
#define IOSK_OFFSET_OK(x)       (round_page(x) == (x))

static vm_tag_t
getVMTagForMap( vm_map_t map )
{
	return (map == kernel_map) ?
	       VM_KERN_MEMORY_SKYWALK : VM_MEMORY_SKYWALK;
}

class IOSKMemoryArray : public IOMultiMemoryDescriptor
{
	OSDeclareFinalStructors( IOSKMemoryArray );

public:
	bool overwriteMappingInTask(
		task_t              intoTask,
		mach_vm_address_t * startAddr,
		IOOptionBits        options );
};

class IOSKMemoryBuffer : public IOBufferMemoryDescriptor
{
	OSDeclareFinalStructors( IOSKMemoryBuffer );

public:
	bool initWithSpec( task_t            inTask,
	    mach_vm_size_t    capacity,
	    mach_vm_address_t alignment,
	    const IOSKMemoryBufferSpec * spec );

	virtual void * getBytesNoCopy( void ) APPLE_KEXT_OVERRIDE;

	virtual void * getBytesNoCopy(vm_size_t start, vm_size_t withLength) APPLE_KEXT_OVERRIDE;

	bool
	isWired( void ) const
	{
		return _wireCount != 0;
	}

	IOSKMemoryBufferSpec    fSpec;
	void                    *fKernelAddr;
	IOMemoryMap             *fKernelReadOnlyMapping;

protected:
	virtual void taggedRelease(const void *tag = NULL) const APPLE_KEXT_OVERRIDE;
	virtual void free( void ) APPLE_KEXT_OVERRIDE;
};

// FIXME: rename IOSKMemoryBuffer -> IOSKBuffer
typedef IOSKMemoryBuffer    IOSKBuffer;

// IOSKRegionMapper:
// Tracks all memory mappings of a single IOSKRegion, with an array of
// IOMemoryMaps to map the region's memory segments.
// Created and released by the parent IOSKMapper.

class IOSKRegionMapper : public OSObject
{
	OSDeclareFinalStructors( IOSKRegionMapper );

public:
	bool initWithMapper( IOSKMapper * mapper, IOSKRegion * region,
	    IOSKOffset regionOffset );

	IOReturn    map( IOSKIndex segIndex, IOSKBuffer * buffer );
	void        unmap( IOSKIndex segIndex, vm_prot_t prot );

	kern_return_t mapOverwrite( vm_map_offset_t addr,
	    vm_map_size_t size, vm_prot_t prot );

private:
	virtual void free( void ) APPLE_KEXT_OVERRIDE;

	IOSKMapper *        fMapper;
	IOSKRegion *        fRegion;
	IOMemoryMap **      fMemoryMaps;
	IOSKCount           fMemoryMapCount;
	IOSKOffset          fRegionOffset;
};

// IOSKMapper:
// Manages all memory mappings of a single task, with an array of
// IOSKRegionMappers to map all memory regions of a memory arena.
// Retains the IOSKArena.

class IOSKMapper : public OSObject
{
	OSDeclareFinalStructors( IOSKMapper );
	friend class IOSKRegionMapper;

public:
	bool     initWithTask( task_t task, IOSKArena * arena );

	IOReturn map( IOSKIndex regIndex, IOSKIndex segIndex, IOSKBuffer * buffer );
	void     unmap( IOSKIndex regIndex, IOSKIndex segIndex, vm_prot_t prot );

	mach_vm_address_t
	getMapAddress( mach_vm_size_t * size ) const
	{
		if (size) {
			*size = fMapSize;
		}
		return fMapAddr;
	}

	IOSKArena *
	getArena( void ) const
	{
		return fArena;
	}
	bool
	isRedirected( void ) const
	{
		return fRedirected;
	}
	void
	redirectMap( void )
	{
		fRedirected = true;
	}

private:
	virtual void free( void ) APPLE_KEXT_OVERRIDE;

	task_t              fTask;
	vm_map_t            fTaskMap;
	IOSKArena *         fArena;
	OSArray *           fSubMaps;
	mach_vm_address_t   fMapAddr;
	mach_vm_size_t      fMapSize;
	bool                fRedirected;
};

// IOSKArena:
// An array of IOSKRegions is used to create an IOSKArena.
// One or more IOSKMapper can map the arena memory to tasks.
// Retains the IOSKRegions, also circularly retains the IOSKMapper(s)
// until the client calls IOSKMapperDestroy().

class IOSKArena : public OSObject
{
	OSDeclareFinalStructors( IOSKArena );

public:
	bool     initWithRegions( IOSKRegion ** regions,
	    IOSKCount regionCount );

	IOReturn createMapperForTask( task_t task,
	    LIBKERN_RETURNS_RETAINED IOSKMapper ** mapper );
	void     redirectMap( IOSKMapper * mapper );

	IOSKSize
	getArenaSize( void ) const
	{
		return fArenaSize;
	}
	IOSKCount
	getRegionCount( void ) const
	{
		return fRegions->getCount();
	}
	IOSKRegion * getRegion( IOSKIndex regIndex ) const;

	IOReturn map( const IOSKRegion * region,
	    IOSKOffset regionOffset,
	    IOSKIndex regionIndex,
	    IOSKIndex segmentIndex,
	    IOSKMemoryBuffer * buffer );

	void     unmap( const IOSKRegion * region,
	    IOSKOffset regionOffset,
	    IOSKIndex regionIndex,
	    IOSKIndex segmentIndex,
	    vm_prot_t prot,
	    bool isRedirected,
	    const void * context );

	bool     addMapper( const IOSKMapper * mapper );
	void     removeMapper( const IOSKMapper * mapper );

private:
	virtual void free( void ) APPLE_KEXT_OVERRIDE;

	IOLock *        fArenaLock;
	OSSet *         fMappers;
	OSArray *       fRegions;
	IOSKSize        fArenaSize;
};

// IOSKRegion:
// An IOSKRegion manages a dynamic array of IOSKBuffers representing each
// memory segment in the region. Each IOSKRegion can be shared by multiple
// IOSKArenas, and the IOSKRegion keeps state specific to each arena - the
// offset and the index of the region within the arena. A lock is used to
// serialize updates to the IOSKBuffer array and the arenas.
// Retains the IOSKBuffers.

class IOSKRegion : public OSObject
{
	OSDeclareFinalStructors( IOSKRegion );

public:
	bool     initWithSpec( const IOSKRegionSpec * spec,
	    IOSKSize segSize, IOSKCount segCount );

	IOReturn setSegmentBuffer( IOSKIndex index, IOSKBuffer * buf );
	void     clearSegmentBuffer( IOSKIndex index, IOSKMemoryBufferRef * prevBuffer );

	bool     attachArena( IOSKArena * arena,
	    IOSKOffset regionOffset, IOSKIndex regionIndex );
	void     detachArena( const IOSKArena * arena );

	IOReturn updateMappingsForArena( IOSKArena * arena, bool redirect,
	    const void * context = NULL );

	IOSKCount
	getSegmentCount( void ) const
	{
		return fSegmentCount;
	}
	IOSKSize
	getSegmentSize( void ) const
	{
		return fSegmentSize;
	}
	IOSKSize
	getRegionSize( void ) const
	{
		return fSegmentCount * fSegmentSize;
	}

private:
	virtual void free( void ) APPLE_KEXT_OVERRIDE;

	struct Segment {
		IOSKBuffer *  fBuffer;
	};

	struct ArenaEntry {
		SLIST_ENTRY(ArenaEntry) link;
		IOSKArena *   fArena;
		IOSKOffset    fRegionOffset;
		IOSKIndex     fRegionIndex;
	};
	SLIST_HEAD(ArenaHead, ArenaEntry);

	IOReturn _setSegmentBuffer( const IOSKIndex index, IOSKMemoryBuffer * buf );
	void     _clearSegmentBuffer( const IOSKIndex index, IOSKMemoryBufferRef * prevBuffer );
	ArenaEntry * findArenaEntry( const IOSKArena * arena );

	IOSKRegionSpec fSpec;
	IOLock *    fRegionLock;
	ArenaHead   fArenaHead;
	Segment *   fSegments;
	IOSKCount   fSegmentCount;
	IOSKSize    fSegmentSize;
};

#undef  super
#define super OSObject
OSDefineMetaClassAndFinalStructors( IOSKRegionMapper, OSObject )

bool
IOSKRegionMapper::initWithMapper(
	IOSKMapper * mapper, IOSKRegion * region, IOSKOffset regionOffset )
{
	if ((mapper == NULL) || (region == NULL) || !super::init()) {
		return false;
	}

	// parent mapper retains the arena, which retains the regions
	assert(IOSK_OFFSET_OK(regionOffset));
	fMapper = mapper;
	fRegion = region;
	fRegionOffset = regionOffset;

	fMemoryMapCount = region->getSegmentCount();
	assert(fMemoryMapCount != 0);
	fMemoryMaps = IONew(IOMemoryMap *, fMemoryMapCount);
	if (!fMemoryMaps) {
		return false;
	}

	bzero(fMemoryMaps, sizeof(IOMemoryMap *) * fMemoryMapCount);

	DLOG("SKRegionMapper %p mapper %p region %p offset 0x%x",
	    this, mapper, region, regionOffset);
	return true;
}

void
IOSKRegionMapper::free( void )
{
	DLOG("SKRegionMapper %p", this);

	if (fMemoryMaps) {
		assert(fMemoryMapCount != 0);
		for (IOSKIndex i = 0; i < fMemoryMapCount; i++) {
			if (fMemoryMaps[i]) {
				fMemoryMaps[i]->release();
				fMemoryMaps[i] = NULL;
			}
		}
		IODelete(fMemoryMaps, IOMemoryMap *, fMemoryMapCount);
		fMemoryMaps = NULL;
		fMemoryMapCount = 0;
	}

	fMapper = NULL;
	fRegion = NULL;
	super::free();
}

IOReturn
IOSKRegionMapper::map( IOSKIndex segIndex, IOSKBuffer * buffer )
{
	mach_vm_address_t   addr;
	mach_vm_offset_t    offset;
	IOMemoryMap *       map;
	IOOptionBits        options = kIOMapOverwrite;
	IOReturn            ret = kIOReturnSuccess;

	assert(segIndex < fMemoryMapCount);
	assert(buffer != NULL);

	if ((segIndex >= fMemoryMapCount) || (buffer == NULL)) {
		return kIOReturnBadArgument;
	}

	// redundant map requests are expected when the arena is mapped
	// by more than one mapper.
	if ((map = fMemoryMaps[segIndex]) != NULL) {
		assert(map->getMemoryDescriptor() == buffer);
		return kIOReturnSuccess;
	}

	if (buffer->fSpec.user_writable == FALSE) {
		options |= kIOMapReadOnly;
	}

	offset = fRegionOffset + (segIndex * fRegion->getSegmentSize());
	assert((offset + fRegion->getSegmentSize()) <= fMapper->fMapSize);
	addr = fMapper->fMapAddr + offset;

	map = buffer->createMappingInTask(fMapper->fTask, addr, options);
	fMemoryMaps[segIndex] = map;
	assert((map == NULL) || (map->getLength() == fRegion->getSegmentSize()));
	if (map == NULL) {
		ret = kIOReturnVMError;
	}

	SK_DF(ret == kIOReturnSuccess ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "%p buffer %p index %u map %p offset 0x%x size 0x%x",
	    this, buffer, segIndex, fMemoryMaps[segIndex],
	    (uint32_t)offset, fRegion->getSegmentSize());

	return ret;
}

void
IOSKRegionMapper::unmap( IOSKIndex segIndex, vm_prot_t prot )
{
	mach_vm_address_t   addr;
	mach_vm_offset_t    offset;
	IOMemoryMap *       map;
	kern_return_t       kr;

	assert(segIndex < fMemoryMapCount);

	// redundant unmap requests are expected when the arena is mapped
	// by more than one mapper.
	if ((segIndex >= fMemoryMapCount) || ((map = fMemoryMaps[segIndex]) == NULL)) {
		return;
	}

	offset = fRegionOffset + (segIndex * fRegion->getSegmentSize());
	assert((offset + fRegion->getSegmentSize()) <= fMapper->fMapSize);
	addr = fMapper->fMapAddr + offset;

	kr = mapOverwrite(addr, fRegion->getSegmentSize(), prot);
	assert(KERN_SUCCESS == kr);

	map->release();
	fMemoryMaps[segIndex] = map = NULL;

	DLOG("SKRegionMapper %p index %u offset 0x%x size 0x%x",
	    this, segIndex, (uint32_t)offset, fRegion->getSegmentSize());
}

kern_return_t
IOSKRegionMapper::mapOverwrite(
	vm_map_offset_t addr, vm_map_size_t size, vm_prot_t prot )
{
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_FIXED();
	kern_return_t kr;

	vmk_flags.vmf_overwrite = true;
	vmk_flags.vm_tag = getVMTagForMap(fMapper->fTaskMap);

	kr = vm_map_enter_mem_object(
		fMapper->fTaskMap,
		&addr,
		size,
		(vm_map_offset_t)0,
		vmk_flags,
		IPC_PORT_NULL,
		(vm_object_offset_t)0,
		FALSE,
		prot,
		VM_PROT_DEFAULT,
		VM_INHERIT_NONE);

	SK_DF(kr == KERN_SUCCESS ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "SKRegionMapper %p addr 0x%llx size 0x%llx prot 0x%x "
	    "kr 0x%x", this, (uint64_t)addr, (uint64_t)size, prot, kr);
	return kr;
}

#undef  super
#define super OSObject
OSDefineMetaClassAndFinalStructors( IOSKMapper, OSObject )

bool
IOSKMapper::initWithTask(
	task_t task, IOSKArena * arena )
{
	IOSKRegionMapper *  subMap;
	IOSKRegion *        region;
	IOSKCount           regionCount;
	IOSKOffset          regionOffset = 0;
	vm_map_offset_t     addr;
	vm_map_size_t       size;
	kern_return_t       kr;
	bool    ok = false;

	if ((task == TASK_NULL) || (arena == NULL) || !super::init()) {
		return false;
	}

	fTask = task;
	fTaskMap = get_task_map(task);
	if (fTaskMap == VM_MAP_NULL) {
		return false;
	}

	arena->retain();
	fArena = arena;

	regionCount = fArena->getRegionCount();
	assert(regionCount != 0);

	fSubMaps = OSArray::withCapacity(regionCount);
	if (!fSubMaps) {
		return false;
	}

	for (IOSKIndex i = 0; i < regionCount; i++) {
		region = fArena->getRegion(i);
		assert(region != NULL);

		subMap = new IOSKRegionMapper;
		if (subMap && !subMap->initWithMapper(this, region, regionOffset)) {
			subMap->release();
			subMap = NULL;
		}
		if (!subMap) {
			break;
		}

		// array retains the regions
		ok = fSubMaps->setObject(subMap);
		subMap->release();
		subMap = NULL;
		if (!ok) {
			break;
		}

		// offset of next region
		regionOffset += region->getRegionSize();
	}
	if (fSubMaps->getCount() != regionCount) {
		return false;
	}

	addr = 0;
	size = fArena->getArenaSize();
	assert(regionOffset == size);
	assert(IOSK_SIZE_OK(size));

	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
	vmk_flags.vm_tag = getVMTagForMap(fTaskMap);

	// reserve address space on given task with PROT_NONE
	kr = vm_map_enter_mem_object(
		fTaskMap,
		&addr,
		size,
		(vm_map_offset_t)0,
		vmk_flags,
		IPC_PORT_NULL,
		(vm_object_offset_t)0,
		FALSE,
		VM_PROT_NONE,
		VM_PROT_DEFAULT,
		VM_INHERIT_NONE);

	ok = false;
	if (KERN_SUCCESS == kr) {
		fMapAddr = (mach_vm_address_t)addr;
		fMapSize = (mach_vm_size_t)size;
		ok = true;
	}

	SK_DF(kr == KERN_SUCCESS ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "SKMapper %p task 0x%llx map %p addr 0x%llx size 0x%llx subMaps %u "
	    "kr 0x%x", this, (uint64_t)task, fTaskMap, (uint64_t)addr,
	    (uint64_t)size, fSubMaps->getCount(), kr);


	return ok;
}

void
IOSKMapper::free( void )
{
	DLOG("SKMapper %p", this);

	if (fSubMaps != NULL) {
		fSubMaps->release();
		fSubMaps = NULL;
	}

	if (fArena != NULL) {
		fArena->release();
		fArena = NULL;
	}

	if (fMapSize != 0) {
		mach_vm_deallocate(fTaskMap, fMapAddr, fMapSize);
		fTaskMap = NULL;
		fMapAddr = 0;
		fMapSize = 0;
	}

	fTask = NULL;
	fTaskMap = NULL;

	super::free();
}

IOReturn
IOSKMapper::map(
	IOSKIndex regionIndex, IOSKIndex segmentIndex, IOSKBuffer * buffer )
{
	IOSKRegionMapper * subMap;
	IOReturn ret = kIOReturnBadArgument;

	// route to the region mapper at regionIndex
	assert(regionIndex < fSubMaps->getCount());
	subMap = (typeof(subMap))fSubMaps->getObject(regionIndex);
	if (subMap) {
		ret = subMap->map(segmentIndex, buffer);
	}

	return ret;
}

void
IOSKMapper::unmap(
	IOSKIndex regionIndex, IOSKIndex segmentIndex, vm_prot_t prot )
{
	IOSKRegionMapper * subMap;

	// route to the region mapper at regionIndex
	assert(regionIndex < fSubMaps->getCount());
	subMap = (typeof(subMap))fSubMaps->getObject(regionIndex);
	if (subMap) {
		subMap->unmap(segmentIndex, prot);
	}
}

#undef  super
#define super OSObject
OSDefineMetaClassAndFinalStructors( IOSKArena, OSObject )

bool
IOSKArena::initWithRegions(
	IOSKRegion ** regions, IOSKCount regionCount )
{
	IOSKRegion * region;
	IOSKSize     regionSize;
	IOSKOffset   regionOffset = 0;
	bool         ok = false;

	assert(regions != NULL);
	assert(regionCount != 0);

	do {
		if ((regions == NULL) || (regionCount == 0) || !super::init()) {
			break;
		}

		fArenaLock = IOLockAlloc();
		if (fArenaLock == NULL) {
			break;
		}

		fRegions = OSArray::withObjects((const OSObject **)regions, regionCount);
		if (!fRegions) {
			break;
		}

		ok = true;
		for (uint32_t i = 0; i < regionCount; i++) {
			region = OSDynamicCast(IOSKRegion, fRegions->getObject(i));
			ok = (region != NULL);
			if (!ok) {
				break;
			}

			regionSize = region->getRegionSize();
			assert(IOSK_SIZE_OK(regionSize));

			// attach to each region and assign region offset/index
			ok = region->attachArena(this, regionOffset, i);
			if (!ok) {
				break;
			}

			// offset of next region
			regionOffset += regionSize;
			assert(IOSK_OFFSET_OK(regionOffset));
		}
		fArenaSize = regionOffset;
	} while (false);

	DLOG("SKArena %p regions %u size 0x%x ok %d",
	    this, regionCount, fArenaSize, ok);
	return ok;
}

void
IOSKArena::free( void )
{
	DLOG("IOSKArena %p", this);

	if (fRegions) {
		IOSKRegion * region;
		OSObject * object;

		// detach from regions to stop mapping requests
		for (uint32_t i = 0; (object = fRegions->getObject(i)); i++) {
			region = OSDynamicCast(IOSKRegion, object);
			if (region) {
				region->detachArena(this);
			}
		}

		fRegions->release();
		fRegions = NULL;
	}

	if (fMappers) {
		assert(fMappers->getCount() == 0);
		fMappers->release();
		fMappers = NULL;
	}

	if (fArenaLock != NULL) {
		IOLockFree(fArenaLock);
		fArenaLock = NULL;
	}

	super::free();
}

IOReturn
IOSKArena::createMapperForTask( task_t task, IOSKMapper ** outMapper )
{
	IOSKRegion * region;
	OSObject *   object;
	IOSKMapper * mapper;
	IOReturn     result, ret = kIOReturnSuccess;

	assert(task != TASK_NULL);
	assert(outMapper != NULL);

	mapper = new IOSKMapper;
	if (mapper && !mapper->initWithTask(task, this)) {
		mapper->release();
		mapper = NULL;
	}
	if (!mapper || !addMapper(mapper)) {
		ret = kIOReturnNoMemory;
		goto done;
	}

	// request all regions to refresh the arena's mappings,
	// which now includes the newly added mapper.
	for (uint32_t i = 0; (object = fRegions->getObject(i)); i++) {
		region = OSDynamicCast(IOSKRegion, object);
		assert(region != NULL);
		result = region->updateMappingsForArena(this, false);
		assert(kIOReturnSuccess == result);
		if (result != kIOReturnSuccess) {
			ret = result;
		}
	}

done:
	if ((ret != kIOReturnSuccess) && mapper) {
		mapper->release();
		mapper = NULL;
	}
	*outMapper = mapper;
	return ret;
}

IOReturn
IOSKArena::map(
	const IOSKRegion * region __unused,
	IOSKOffset regionOffset __unused,
	IOSKIndex regionIndex, IOSKIndex segmentIndex,
	IOSKBuffer * buffer )
{
	IOSKMapper * mapper;
	OSIterator * iter;
	IOReturn result, ret = kIOReturnSuccess;

	IOLockLock(fArenaLock);

	if (fMappers && (iter = OSCollectionIterator::withCollection(fMappers))) {
		while ((mapper = (typeof(mapper))iter->getNextObject())) {
			// skip any redirected mapper
			if (mapper->isRedirected()) {
				continue;
			}
			result = mapper->map(regionIndex, segmentIndex, buffer);
			assert(kIOReturnSuccess == result);
			if (result != kIOReturnSuccess) {
				ret = result;
			}
		}
		iter->release();
	}

	IOLockUnlock(fArenaLock);
	return ret;
}

void
IOSKArena::unmap(
	const IOSKRegion * region __unused,
	IOSKOffset regionOffset __unused,
	IOSKIndex regionIndex, IOSKIndex segmentIndex,
	vm_prot_t prot, bool redirecting, const void * context )
{
	IOSKMapper * mapper;
	const IOSKMapper * redirectMapper = (typeof(redirectMapper))context;
	OSIterator * iter;

	IOLockLock(fArenaLock);

	if (fMappers && (iter = OSCollectionIterator::withCollection(fMappers))) {
		while ((mapper = (typeof(mapper))iter->getNextObject())) {
			if (redirecting) {
				if ((redirectMapper == NULL) || (redirectMapper == mapper)) {
					// redirecting can be specific to one mapper
					mapper->unmap(regionIndex, segmentIndex, prot);
					mapper->redirectMap();
				}
			} else if (!mapper->isRedirected()) {
				mapper->unmap(regionIndex, segmentIndex, prot);
			}
		}
		iter->release();
	}

	IOLockUnlock(fArenaLock);
}

void
IOSKArena::redirectMap( IOSKMapper * mapper )
{
	OSObject *   object;
	IOSKRegion * region;
	IOReturn     ret;

	// request all (redirectable) regions to redirect the arena's mapper,
	// mapper=0 will redirect all mappers.

	for (uint32_t i = 0; (object = fRegions->getObject(i)); i++) {
		region = OSDynamicCast(IOSKRegion, object);
		assert(region != NULL);
		ret = region->updateMappingsForArena(this, true, (const void *)mapper);
		assert(kIOReturnSuccess == ret);
	}
}

IOSKRegion *
IOSKArena::getRegion( IOSKIndex regionIndex ) const
{
	assert(regionIndex < getRegionCount());
	return OSDynamicCast(IOSKRegion, fRegions->getObject(regionIndex));
}

bool
IOSKArena::addMapper( const IOSKMapper * mapper )
{
	bool ok = false;

	assert(mapper != NULL);
	if (!mapper) {
		return false;
	}

	IOLockLock(fArenaLock);

	if (!fMappers) {
		fMappers = OSSet::withCapacity(2);
	}
	if (fMappers) {
		ok = fMappers->setObject(mapper);
	}

	IOLockUnlock(fArenaLock);

	DLOG("arena %p mapper %p ok %d", this, mapper, ok);
	return ok;
}

void
IOSKArena::removeMapper( const IOSKMapper * mapper )
{
	assert(mapper != NULL);
	if (!mapper) {
		return;
	}

	IOLockLock(fArenaLock);

	if (fMappers) {
		fMappers->removeObject(mapper);
	}

	IOLockUnlock(fArenaLock);
	DLOG("arena %p mapper %p", this, mapper);
}

#undef  super
#define super OSObject
OSDefineMetaClassAndFinalStructors( IOSKRegion, OSObject )

bool
IOSKRegion::initWithSpec( const IOSKRegionSpec * spec,
    IOSKSize segmentSize, IOSKCount segmentCount )
{
	bool ok = false;

	do {
		if (!IOSK_SIZE_OK(segmentSize) || (segmentCount == 0) || !super::init()) {
			break;
		}

		if (spec) {
			fSpec = *spec;
		}
		fSegmentCount = segmentCount;
		fSegmentSize = segmentSize;

		fRegionLock = IOLockAlloc();
		if (fRegionLock == NULL) {
			break;
		}

		SLIST_INIT(&fArenaHead);

		fSegments = IONew(Segment, fSegmentCount);
		if (fSegments == NULL) {
			break;
		}
		bzero(fSegments, sizeof(IOSKRegion::Segment) * fSegmentCount);
		ok = true;
	} while (false);

	SK_DF(ok ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "SKRegion %p segment size 0x%x count %u ok %d",
	    this, segmentSize, segmentCount, ok);

	return ok;
}

void
IOSKRegion::free( void )
{
	DLOG("SKRegion %p", this);

	ArenaEntry *entry, *tentry;
	SLIST_FOREACH_SAFE(entry, &fArenaHead, link, tentry) {
		SLIST_REMOVE(&fArenaHead, entry, ArenaEntry, link);
		// Arena didn't detach from the region before release()
		assert(entry->fArena == NULL);
		IOFreeType(entry, ArenaEntry);
	}
	assert(SLIST_EMPTY(&fArenaHead));

	if (fSegments != NULL) {
		assert(fSegmentCount != 0);
		for (uint32_t i = 0; i < fSegmentCount; i++) {
			_clearSegmentBuffer(i, NULL);
		}

		IODelete(fSegments, Segment, fSegmentCount);
		fSegments = NULL;
	}

	if (fRegionLock != NULL) {
		IOLockFree(fRegionLock);
		fRegionLock = NULL;
	}

	super::free();
}

IOReturn
IOSKRegion::_setSegmentBuffer(
	const IOSKIndex segmentIndex, IOSKBuffer * buffer )
{
	Segment *   seg;
	IOReturn    ret = kIOReturnSuccess;

	assert(buffer != NULL);
	assert(segmentIndex < fSegmentCount);

	if (!buffer || (buffer->getCapacity() != fSegmentSize) ||
	    (segmentIndex >= fSegmentCount)) {
		ret = kIOReturnBadArgument;
		goto done;
	}

	seg = &fSegments[segmentIndex];
	assert(seg->fBuffer == NULL);

	if (seg->fBuffer == NULL) {
		buffer->retain();
		seg->fBuffer = buffer;

		// update mappings for all arenas containing this region,
		// or none if no arena is attached.
		ArenaEntry * entry;
		SLIST_FOREACH(entry, &fArenaHead, link) {
			if (entry->fArena != NULL) {
				ret = entry->fArena->map(this,
				    entry->fRegionOffset, entry->fRegionIndex,
				    segmentIndex, buffer);
				assert(kIOReturnSuccess == ret);
				if (ret != kIOReturnSuccess) {
					break;
				}
			}
		}
	}

	if (ret != kIOReturnSuccess) {
		_clearSegmentBuffer(segmentIndex, NULL);
	}

done:
	SK_DF(ret == kIOReturnSuccess ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "SKRegion %p set segment[%u] buffer %p ret 0x%x",
	    this, segmentIndex, buffer, ret);

	return ret;
}

void
IOSKRegion::_clearSegmentBuffer(
	const IOSKIndex segmentIndex, IOSKMemoryBufferRef * prevBuffer  )
{
	Segment * seg;
	bool cleared = false;
	IOSKBuffer * foundBuffer = NULL;

	assert(segmentIndex < fSegmentCount);
	if (segmentIndex >= fSegmentCount) {
		goto done;
	}

	seg = &fSegments[segmentIndex];
	if (seg->fBuffer != NULL) {
		foundBuffer = seg->fBuffer;

		// update mappings for all arenas containing this region,
		// or none if no arena is attached.
		vm_prot_t prot = VM_PROT_NONE;
		ArenaEntry * entry;

		SLIST_FOREACH(entry, &fArenaHead, link) {
			if (entry->fArena != NULL) {
				entry->fArena->unmap(this,
				    entry->fRegionOffset, entry->fRegionIndex,
				    segmentIndex, prot, false, NULL);
			}
		}

		seg->fBuffer->release();
		seg->fBuffer = NULL;
		cleared = true;
	}

	if (prevBuffer) {
		*prevBuffer = foundBuffer;
	}

done:
	DLOG("SKRegion %p clear segment[%u] ok %d",
	    this, segmentIndex, cleared);
}

IOReturn
IOSKRegion::setSegmentBuffer(
	IOSKIndex index, IOSKMemoryBuffer * buffer )
{
	IOReturn ret;

	IOLockLock(fRegionLock);
	ret = _setSegmentBuffer(index, buffer);
	IOLockUnlock(fRegionLock);
	return ret;
}

void
IOSKRegion::clearSegmentBuffer( IOSKIndex index, IOSKMemoryBufferRef * prevBuffer )
{
	IOLockLock(fRegionLock);
	_clearSegmentBuffer(index, prevBuffer);
	IOLockUnlock(fRegionLock);
}

IOSKRegion::ArenaEntry *
IOSKRegion::findArenaEntry( const IOSKArena * arena )
{
	ArenaEntry * found = NULL;

	assert(arena != NULL);

	ArenaEntry * entry;
	SLIST_FOREACH(entry, &fArenaHead, link) {
		if (entry->fArena == arena) {
			found = entry;
			break;
		}
	}
	return found;
}

bool
IOSKRegion::attachArena(
	IOSKArena * arena, IOSKOffset regionOffset, IOSKIndex regionIndex )
{
	bool ok = false;

	assert(arena != NULL);
	if (!arena) {
		return false;
	}

	IOLockLock(fRegionLock);

	ArenaEntry * entry = NULL;
	ArenaEntry * empty = NULL;
	ArenaEntry * dup = NULL;

	SLIST_FOREACH(entry, &fArenaHead, link) {
		// duplicates not allowed
		assert(entry->fArena != arena);
		if (entry->fArena == arena) {
			dup = entry;
			break;
		}

		if ((empty == NULL) && (entry->fArena == NULL)) {
			empty = entry;
		}
	}

	if (dup != NULL) {
		// do nothing
	} else if (empty != NULL) {
		// update the empty/available entry
		empty->fArena = arena;
		empty->fRegionOffset = regionOffset;
		empty->fRegionIndex = regionIndex;
		ok = true;
	} else {
		// append a new entry
		ArenaEntry * newEntry = IOMallocType(ArenaEntry);
		newEntry->fArena = arena;
		newEntry->fRegionOffset = regionOffset;
		newEntry->fRegionIndex = regionIndex;
		SLIST_INSERT_HEAD(&fArenaHead, newEntry, link);
		ok = true;
	}

	IOLockUnlock(fRegionLock);

	SK_DF(ok ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "SKRegion %p attach arena %p offset 0x%x index %u ok %d",
	    this, arena, regionOffset, regionIndex, ok);
	return ok;
}

void
IOSKRegion::detachArena( const IOSKArena * arena )
{
	ArenaEntry * entry;
	bool detached = false;

	assert(arena != NULL);
	if (!arena) {
		return;
	}

	IOLockLock(fRegionLock);

	entry = findArenaEntry(arena);
	if (entry != NULL) {
		entry->fArena = NULL;
		entry->fRegionOffset = 0;
		entry->fRegionIndex = 0;
		detached = true;
	}

	IOLockUnlock(fRegionLock);
	DLOG("SKRegion %p detach arena %p ok %d", this, arena, detached);
}

IOReturn
IOSKRegion::updateMappingsForArena(
	IOSKArena * arena, bool redirect, const void * context )
{
	ArenaEntry * entry;
	Segment *   seg;
	vm_prot_t   prot;
	IOReturn    result = kIOReturnSuccess;

	assert(arena != NULL);
	if (redirect && fSpec.noRedirect) {
		DLOG("SKRegion %p no redirect", this);
		return kIOReturnSuccess;
	}

	IOLockLock(fRegionLock);

	entry = findArenaEntry(arena);
	if (entry != NULL) {
		assert(entry->fArena == arena);

		for (uint32_t index = 0; index < fSegmentCount; index++) {
			seg = &fSegments[index];
			if ((seg->fBuffer == NULL) || redirect) {
				prot = VM_PROT_NONE;
				if (redirect && (seg->fBuffer != NULL)) {
					prot = VM_PROT_READ;
					if (seg->fBuffer->fSpec.user_writable) {
						prot |= VM_PROT_WRITE;
					}
				}

				arena->unmap(this, entry->fRegionOffset, entry->fRegionIndex,
				    index, prot, redirect, context);
			} else {
				result = arena->map(this, entry->fRegionOffset,
				    entry->fRegionIndex,
				    index, seg->fBuffer);
			}
		}
	}

	IOLockUnlock(fRegionLock);
	SK_DF(result == kIOReturnSuccess ? SK_VERB_IOSK : SK_VERB_ERROR,
	    "%p update arena %p redirect %d ret 0x%x",
	    this, arena, redirect, result);
	return result;
}

OSDefineMetaClassAndFinalStructors( IOSKMemoryArray, IOMultiMemoryDescriptor )

bool
IOSKMemoryArray::overwriteMappingInTask(
	task_t              intoTask,
	mach_vm_address_t * startAddr,
	IOOptionBits        options )
{
	bool ok = true;

	for (uint32_t i = 0; i < _descriptorsCount; i++) {
		IOMemoryDescriptor * iomd = _descriptors[i];
		IOSKMemoryBuffer * mb = OSDynamicCast(IOSKMemoryBuffer, iomd);
		IOSKMemoryArray *  ma = OSDynamicCast(IOSKMemoryArray, iomd);

		if (mb) {
			IOMemoryMap * rwMap;

			if (mb->fSpec.user_writable) {
				// overwrite read-only mapping to read-write
				rwMap = mb->createMappingInTask(intoTask,
				    *startAddr, options | kIOMapOverwrite);
				if (rwMap) {
					DLOG("map_rw %d: addr 0x%llx, size 0x%x",
					    i, *startAddr, (uint32_t)iomd->getLength());
					rwMap->release();
				} else {
					ELOG("overwrite map failed");
					ok = false;
					break;
				}
			} else {
				DLOG("map_ro %d: addr 0x%llx, size 0x%x",
				    i, *startAddr, (uint32_t)iomd->getLength());
			}

			//DLOG("map increment 0x%x", (uint32_t)iomd->getLength());
			*startAddr += iomd->getLength();
		} else if (ma) {
			ok = ma->overwriteMappingInTask(intoTask, startAddr, options);
			if (!ok) {
				break;
			}
		}
	}

	return ok;
}

#undef  super
#define super IOBufferMemoryDescriptor
OSDefineMetaClassAndFinalStructorsWithZone( IOSKMemoryBuffer,
    IOBufferMemoryDescriptor, ZC_NONE )

bool
IOSKMemoryBuffer::initWithSpec(
	task_t            inTask,
	mach_vm_size_t    capacity,
	mach_vm_address_t alignment,
	const IOSKMemoryBufferSpec * spec )
{
	bool ok = true;
	IOOptionBits options = kIOMemoryKernelUserShared;

	if (spec) {
		fSpec = *spec;
	}
	if (fSpec.iodir_in) {
		options |= kIODirectionIn;
	}
	if (fSpec.iodir_out) {
		options |= kIODirectionOut;
	}
	if (fSpec.purgeable) {
		options |= (kIOMemoryPageable | kIOMemoryPurgeable);
	}
	if (fSpec.inhibitCache) {
		options |= kIOMapInhibitCache;
	}
	if (fSpec.physcontig) {
		options |= kIOMemoryPhysicallyContiguous;
	}
	if (fSpec.threadSafe) {
		options |= kIOMemoryThreadSafe;
	}

	setVMTags(VM_KERN_MEMORY_SKYWALK, VM_MEMORY_SKYWALK);

	if (fSpec.kernel_writable) {
		if (fSpec.puredata) {
			/* purely data; use data buffers heap */
			ok = initWithPhysicalMask(
				inTask, options, capacity, alignment, 0);
		} else {
			/* may have pointers; use default heap */
			ok = initControlWithPhysicalMask(
				inTask, options, capacity, alignment, 0);
		}
		if (!ok) {
			return false;
		}
		fKernelAddr = super::getBytesNoCopy();
		return true;
	} else {
		/*
		 * To create kernel read-only BMD:
		 * 1. init with TASK_NULL (which isn’t mapped anywhere);
		 * 2. then map read-only into kernel_task
		 * Note that kernel virtual address has to be obtained from
		 * the secondary kernel read-only mapping.
		 */
		options |= kIOMapReadOnly;
		if (fSpec.puredata) {
			/* purely data; use data buffers heap */
			ok = initWithPhysicalMask(
				TASK_NULL, options, capacity, alignment, 0);
		} else {
			/* may have pointers; use default heap */
			ok = initControlWithPhysicalMask(
				TASK_NULL, options, capacity, alignment, 0);
		}
		if (!ok) {
			return false;
		}
		/* RO mapping will retain this, see ::taggedRelease() */
		fKernelReadOnlyMapping = super::createMappingInTask(kernel_task, 0, options);
		if (fKernelReadOnlyMapping == NULL) {
			return false;
		}
		fKernelAddr = (void *)fKernelReadOnlyMapping->getVirtualAddress();
		assert(fKernelAddr != NULL);
		return true;
	}
}

void
IOSKMemoryBuffer::taggedRelease(const void *tag) const
{
	/*
	 * RO buffer has extra retain from fKernelReadOnlyMapping, needs to
	 * explicitly release when refcnt == 2 to free ourselves.
	 */
	if (!fSpec.kernel_writable && fKernelReadOnlyMapping != NULL) {
		super::taggedRelease(tag, 2);
	} else {
		super::taggedRelease(tag);
	}
}

void
IOSKMemoryBuffer::free( void )
{
	if (!fSpec.kernel_writable && fKernelReadOnlyMapping != NULL) {
		OSSafeReleaseNULL(fKernelReadOnlyMapping);
		fKernelAddr = NULL;
	}
	super::free();
}

void *
IOSKMemoryBuffer::getBytesNoCopy( void )
{
	return fKernelAddr;
}

void *
IOSKMemoryBuffer::getBytesNoCopy( vm_size_t start, vm_size_t withLength )
{
	IOVirtualAddress address;

	if ((start + withLength) < start) {
		return NULL;
	}

	address = (IOVirtualAddress) fKernelAddr;

	if (start < _length && (start + withLength) <= _length) {
		return (void *)(address + start);
	}
	return NULL;
}

static IOSKMemoryBuffer *
RefToMemoryBuffer( IOSKMemoryRef inRef )
{
	IOSKMemoryBuffer * mb = OSDynamicCast(IOSKMemoryBuffer, inRef);
	return mb;
}

static IOSKMemoryArray *
RefToMemoryArray( IOSKMemoryRef inRef )
{
	IOSKMemoryArray * ma = OSDynamicCast(IOSKMemoryArray, inRef);
	return ma;
}

__BEGIN_DECLS

void
IOSKMemoryDestroy(
	IOSKMemoryRef reference )
{
	assert(reference);
	if (reference) {
		reference->release();
	}
}

void
IOSKMemoryMapDestroy(
	IOSKMemoryMapRef reference )
{
	assert(reference);
	if (reference) {
		reference->release();
	}
}

IOSKMemoryBufferRef
IOSKMemoryBufferCreate(
	mach_vm_size_t capacity,
	const IOSKMemoryBufferSpec * spec,
	mach_vm_address_t * kvaddr )
{
	IOSKMemoryBuffer * mb;
	void * addr = NULL;

	mach_vm_size_t rounded_capacity = round_page(capacity);
	if (capacity != rounded_capacity) {
		return NULL;
	}

	mb = new IOSKMemoryBuffer;
	if (mb && !mb->initWithSpec(kernel_task, capacity, PAGE_SIZE, spec)) {
		mb->release();
		mb = NULL;
	}
	if (!mb) {
		ELOG("create capacity=0x%llx failed", capacity);
		goto fail;
	}

	addr = mb->fKernelAddr;
	if (kvaddr) {
		*kvaddr = (mach_vm_address_t)(uintptr_t)addr;
	}
	DLOG("buffer %p, vaddr %p, capacity 0x%llx", mb, addr, capacity);

fail:
	return mb;
}

IOSKMemoryArrayRef
IOSKMemoryArrayCreate(
	const IOSKMemoryRef refs[],
	uint32_t count )
{
	IOSKMemoryArray * ma;
	IOSKMemoryRef ref;
	bool ok = true;

	if (!refs || (count < 1)) {
		return NULL;
	}

	// Validate the references
	for (uint32_t i = 0; i < count; i++) {
		ref = refs[i];
		assert(RefToMemoryBuffer(ref) || RefToMemoryArray(ref));
		if (!RefToMemoryBuffer(ref) && !RefToMemoryArray(ref)) {
			ok = false;
			break;
		}
	}
	if (!ok) {
		return NULL;
	}

	ma = new IOSKMemoryArray;
	if (ma && !ma->initWithDescriptors((IOMemoryDescriptor **)refs,
	    count, kIODirectionInOut, false)) {
		ma->release();
		ma = NULL;
	}
	if (!ma) {
		ELOG("create count=%u failed", count);
	} else {
		DLOG("array %p count=%u", ma, count);
	}

	return ma;
}

IOSKMemoryMapRef
IOSKMemoryMapToTask(
	IOSKMemoryRef       reference,
	task_t              intoTask,
	mach_vm_address_t * mapAddr,
	mach_vm_size_t *    mapSize )
{
	IOOptionBits options = kIOMapAnywhere | kIOMapReadOnly;
	mach_vm_address_t startAddr;
	IOMemoryMap * map = NULL;

	IOSKMemoryArray * ma = RefToMemoryArray(reference);

	assert(ma);
	if (!ma) {
		return NULL;
	}

	assert(intoTask != kernel_task);
	map = ma->createMappingInTask(intoTask, 0, options);
	if (map) {
		bool ok;

		startAddr = map->getAddress();
		*mapAddr = startAddr;
		*mapSize = map->getSize();
		DLOG("map vaddr 0x%llx, size 0x%llx", *mapAddr, *mapSize);

		options &= ~(kIOMapReadOnly | kIOMapAnywhere);
		ok = ma->overwriteMappingInTask(intoTask, &startAddr, options);
		if (!ok) {
			map->release();
			map = NULL;
		}
	}
	return map;
}

IOSKMemoryMapRef
IOSKMemoryMapToKernelTask(
	IOSKMemoryRef       reference,
	mach_vm_address_t * mapAddr,
	mach_vm_size_t *    mapSize )
{
	IOOptionBits options = kIOMapAnywhere;
	mach_vm_address_t startAddr;
	IOMemoryMap * map = NULL;

	IOSKMemoryArray * ma = RefToMemoryArray(reference);

	assert(ma);
	if (!ma) {
		return NULL;
	}

	map = ma->createMappingInTask(kernel_task, 0, options);
	if (map) {
		startAddr = map->getAddress();
		*mapAddr = startAddr;
		*mapSize = map->getSize();
		DLOG("map vaddr 0x%llx, size 0x%llx", *mapAddr, *mapSize);
	}
	return map;
}

IOReturn
IOSKMemoryDiscard( IOSKMemoryRef reference )
{
	IOSKMemoryBuffer * mb = RefToMemoryBuffer(reference);

	assert(mb);
	assert(mb->fSpec.purgeable);
	if (!mb || !mb->fSpec.purgeable) {
		return kIOReturnBadArgument;
	}

	return mb->setPurgeable(kIOMemoryPurgeableEmpty |
	           kIOMemoryPurgeableFaultOnAccess, NULL);
}

IOReturn
IOSKMemoryReclaim( IOSKMemoryRef reference )
{
	IOSKMemoryBuffer * mb = RefToMemoryBuffer(reference);

	assert(mb);
	assert(mb->fSpec.purgeable);
	if (!mb || !mb->fSpec.purgeable) {
		return kIOReturnBadArgument;
	}

	return mb->setPurgeable(kIOMemoryPurgeableNonVolatile, NULL);
}

IOReturn
IOSKMemoryWire( IOSKMemoryRef reference )
{
	IOSKMemoryBuffer * mb = RefToMemoryBuffer(reference);

	assert(mb);
	assert(mb->fSpec.purgeable);
	if (!mb || !mb->fSpec.purgeable) {
		return kIOReturnBadArgument;
	}

	return mb->prepare();
}

IOReturn
IOSKMemoryUnwire( IOSKMemoryRef reference )
{
	IOSKMemoryBuffer * mb = RefToMemoryBuffer(reference);

	assert(mb);
	assert(mb->fSpec.purgeable);
	if (!mb || !mb->fSpec.purgeable) {
		return kIOReturnBadArgument;
	}

	return mb->complete();
}

static void
IOSKObjectDestroy( const OSObject * object )
{
	assert(object != NULL);
	if (object) {
		object->release();
	}
}

IOSKArenaRef
IOSKArenaCreate( IOSKRegionRef * regionList, IOSKCount regionCount )
{
	IOSKArenaRef arena;

	arena = new IOSKArena;
	if ((arena != NULL) && !arena->initWithRegions(regionList, regionCount)) {
		arena->release();
		arena = NULL;
	}
	return arena;
}

void
IOSKArenaDestroy( IOSKArenaRef arena )
{
	IOSKObjectDestroy(arena);
}

void
IOSKArenaRedirect( IOSKArenaRef arena )
{
	assert(arena != NULL);
	if (arena != NULL) {
		arena->redirectMap(NULL);
	}
}

IOSKRegionRef
IOSKRegionCreate( const IOSKRegionSpec * regionSpec,
    IOSKSize segSize, IOSKCount segCount )
{
	IOSKRegionRef   region;

	region = new IOSKRegion;
	if ((region != NULL) && !region->initWithSpec(regionSpec, segSize, segCount)) {
		region->release();
		region = NULL;
	}
	return region;
}

void
IOSKRegionDestroy( IOSKRegionRef region )
{
	IOSKObjectDestroy(region);
}

IOReturn
IOSKRegionSetBuffer( IOSKRegionRef region, IOSKIndex segmentIndex,
    IOSKMemoryBufferRef buffer )
{
	IOReturn ret = kIOReturnBadArgument;

	assert(region != NULL);
	if (region != NULL) {
		ret = region->setSegmentBuffer(segmentIndex, (IOSKBuffer *)buffer);
	}

	return ret;
}

void
IOSKRegionClearBuffer( IOSKRegionRef region, IOSKIndex segmentIndex )
{
	assert(region != NULL);
	if (region != NULL) {
		region->clearSegmentBuffer(segmentIndex, NULL);
	}
}

void
IOSKRegionClearBufferDebug( IOSKRegionRef region, IOSKIndex segmentIndex,
    IOSKMemoryBufferRef * prevBufferRef )
{
	assert(region != NULL);
	if (region != NULL) {
		region->clearSegmentBuffer(segmentIndex, prevBufferRef);
	}
}

IOSKMapperRef
IOSKMapperCreate( IOSKArenaRef arena, task_t task )
{
	IOSKMapperRef mapper = NULL;

	assert(arena != NULL);
	if (arena != NULL) {
		arena->createMapperForTask(task, &mapper);
	}
	return mapper;
}

void
IOSKMapperDestroy( IOSKMapperRef mapper )
{
	assert(mapper != NULL);
	if (mapper != NULL) {
		IOSKArena * arena = mapper->getArena();
		assert(arena != NULL);
		arena->removeMapper(mapper);
		IOSKObjectDestroy(mapper);
	}
}

void
IOSKMapperRedirect( IOSKMapperRef mapper )
{
	assert(mapper != NULL);
	if (mapper != NULL) {
		IOSKArena * arena = mapper->getArena();
		assert(arena != NULL);
		arena->redirectMap(mapper);
	}
}

IOReturn
IOSKMapperGetAddress( IOSKMapperRef mapper,
    mach_vm_address_t * address, mach_vm_size_t * size )
{
	assert(mapper != NULL);
	if ((mapper == NULL) || (address == NULL)) {
		return kIOReturnBadArgument;
	}

	*address = mapper->getMapAddress(size);
	return kIOReturnSuccess;
}

boolean_t
IOSKBufferIsWired( IOSKMemoryBufferRef buffer )
{
	assert(buffer != NULL);
	return ((IOSKBuffer *)buffer)->isWired();
}

__END_DECLS

#if DEVELOPMENT || DEBUG

extern int IOSkywalkSupportTest(int x);

int
IOSkywalkSupportTest( int newValue )
{
	static const int kNumRegions = 3;
	static const int kNumBuffers = 6;
	static const int kNumMappers = 3;
	static const int kNumArenas  = 2;

	IOSKMemoryBufferSpec bspec;
	IOSKRegionSpec      rspec;
	IOSKMemoryBufferRef buffers[kNumBuffers];
	mach_vm_address_t   bufkvas[kNumBuffers];
	IOSKRegionRef       regions[kNumRegions];
	IOSKRegionRef       reverse[kNumRegions];
	IOSKArenaRef        arenas[kNumArenas];
	IOSKMapperRef       mappers[kNumMappers];
	mach_vm_address_t   addrs[kNumMappers];
	mach_vm_size_t      size;
	uint32_t            value;
	uint32_t *          ptr;
	IOReturn            ret;

	kprintf("IOSKArena count  : %u\n",
	    IOSKArena::gMetaClass.getInstanceCount());
	kprintf("IOSKRegion count : %u\n",
	    IOSKRegion::gMetaClass.getInstanceCount());
	kprintf("IOSKMapper count : %u, %u (sub maps)\n",
	    IOSKMapper::gMetaClass.getInstanceCount(),
	    IOSKRegionMapper::gMetaClass.getInstanceCount());
	kprintf("IOSKBuffer count : %u\n",
	    IOSKBuffer::gMetaClass.getInstanceCount());

	rspec.noRedirect = true;
	regions[0] = IOSKRegionCreate(&rspec, (IOSKSize) ptoa(1), 2);
	assert(regions[0]);
	rspec.noRedirect = false;
	regions[1] = IOSKRegionCreate(&rspec, (IOSKSize) ptoa(2), 3);
	assert(regions[1]);
	regions[2] = IOSKRegionCreate(&rspec, (IOSKSize) ptoa(3), 4);
	assert(regions[2]);

	reverse[0] = regions[2];
	reverse[1] = regions[1];
	reverse[2] = regions[0];

	arenas[0] = IOSKArenaCreate(regions, 3);
	assert(arenas[0]);
	arenas[1] = IOSKArenaCreate(reverse, 3);
	assert(arenas[1]);

	bzero(&bspec, sizeof(bspec));
	bspec.purgeable = true;
	bspec.user_writable = false;
	buffers[0] = IOSKMemoryBufferCreate(ptoa(1), &bspec, &bufkvas[0]);
	assert(buffers[0]);
	assert(IOSKBufferIsWired(buffers[0]) == false);
	bspec.user_writable = true;
	buffers[1] = IOSKMemoryBufferCreate(ptoa(1), &bspec, &bufkvas[1]);
	assert(buffers[1]);
	buffers[2] = IOSKMemoryBufferCreate(ptoa(2), &bspec, &bufkvas[2]);
	assert(buffers[2]);
	buffers[3] = IOSKMemoryBufferCreate(ptoa(2), &bspec, &bufkvas[3]);
	assert(buffers[3]);
	buffers[4] = IOSKMemoryBufferCreate(ptoa(3), &bspec, &bufkvas[4]);
	assert(buffers[4]);
	buffers[5] = IOSKMemoryBufferCreate(ptoa(3), &bspec, &bufkvas[5]);
	assert(buffers[5]);

	for (int i = 0; i < kNumBuffers; i++) {
		value = 0x534B0000 | i;
		ptr = (uint32_t *)(uintptr_t)bufkvas[i];
		*ptr = value;
		assert(value == *ptr);
	}

	ret = IOSKRegionSetBuffer(regions[0], 0, buffers[0]);
	assert(ret == kIOReturnSuccess);
	ret = IOSKRegionSetBuffer(regions[0], 1, buffers[1]);
	assert(ret == kIOReturnSuccess);
	ret = IOSKRegionSetBuffer(regions[1], 0, buffers[2]);
	assert(ret == kIOReturnSuccess);
	ret = IOSKRegionSetBuffer(regions[1], 1, buffers[3]);
	assert(ret == kIOReturnSuccess);
	ret = IOSKRegionSetBuffer(regions[2], 0, buffers[4]);
	assert(ret == kIOReturnSuccess);
	ret = IOSKRegionSetBuffer(regions[2], 3, buffers[5]);
	assert(ret == kIOReturnSuccess);

	mappers[0] = IOSKMapperCreate(arenas[0], current_task());
	assert(mappers[0]);
	mappers[1] = IOSKMapperCreate(arenas[0], current_task());
	assert(mappers[1]);
	mappers[2] = IOSKMapperCreate(arenas[1], current_task());
	assert(mappers[2]);

	ret = IOSKMapperGetAddress(mappers[0], &addrs[0], &size);
	assert(ret == kIOReturnSuccess);
	assert(size == ptoa(20));
	ret = IOSKMapperGetAddress(mappers[1], &addrs[1], &size);
	assert(ret == kIOReturnSuccess);
	assert(size == ptoa(20));
	ret = IOSKMapperGetAddress(mappers[2], &addrs[2], &size);
	assert(ret == kIOReturnSuccess);
	assert(size == ptoa(20));

	for (int i = 0; i < kNumMappers; i++) {
		kprintf("mapper[%d] %p map address 0x%llx size 0x%x\n",
		    i, mappers[i], (uint64_t)addrs[i], (uint32_t)size);
	}

	ptr = (uint32_t *)(uintptr_t)addrs[0];
	assert(*ptr == 0x534B0000);
	ptr = (uint32_t *)(uintptr_t)(addrs[0] + ptoa(1));
	assert(*ptr == 0x534B0001);
	ptr = (uint32_t *)(uintptr_t)(addrs[0] + ptoa(2));
	assert(*ptr == 0x534B0002);
	ptr = (uint32_t *)(uintptr_t)(addrs[0] + ptoa(4));
	assert(*ptr == 0x534B0003);
	ptr = (uint32_t *)(uintptr_t)(addrs[0] + ptoa(8));
	assert(*ptr == 0x534B0004);
	ptr = (uint32_t *)(uintptr_t)(addrs[0] + ptoa(17));
	assert(*ptr == 0x534B0005);

	*ptr = 0x4B530005;
	assert(0x4B530005 == *ptr);
	*ptr = 0x534B0005;

	IOSKMapperRedirect(mappers[0]);
	*ptr = 0x33333333;
	assert(0x33333333 == *ptr);
	ptr = (uint32_t *)(uintptr_t)addrs[0];
	assert(*ptr == 0x534B0000);

	ptr = (uint32_t *)(uintptr_t)addrs[2];
	assert(*ptr == 0x534B0004);
	ptr = (uint32_t *)(uintptr_t)(addrs[2] + ptoa(9));
	assert(*ptr == 0x534B0005);
	ptr = (uint32_t *)(uintptr_t)(addrs[2] + ptoa(12));
	assert(*ptr == 0x534B0002);
	ptr = (uint32_t *)(uintptr_t)(addrs[2] + ptoa(14));
	assert(*ptr == 0x534B0003);
	ptr = (uint32_t *)(uintptr_t)(addrs[2] + ptoa(18));
	assert(*ptr == 0x534B0000);
	ptr = (uint32_t *)(uintptr_t)(addrs[2] + ptoa(19));
	assert(*ptr == 0x534B0001);

	IOSKRegionClearBufferDebug(regions[0], 1, NULL);
	ret = IOSKRegionSetBuffer(regions[0], 1, buffers[1]);
	assert(ret == kIOReturnSuccess);
	assert(*ptr == 0x534B0001);

	IOSKArenaRedirect(arenas[0]);
	IOSKArenaRedirect(arenas[1]);

	for (int i = 0; i < kNumBuffers; i++) {
		IOSKMemoryDestroy(buffers[i]);
	}
	for (int i = 0; i < kNumRegions; i++) {
		IOSKRegionDestroy(regions[i]);
	}
	for (int i = 0; i < kNumArenas; i++) {
		IOSKArenaDestroy(arenas[i]);
	}
	for (int i = 0; i < kNumMappers; i++) {
		IOSKMapperDestroy(mappers[i]);
	}

	kprintf("IOSKArena count  : %u\n",
	    IOSKArena::gMetaClass.getInstanceCount());
	kprintf("IOSKRegion count : %u\n",
	    IOSKRegion::gMetaClass.getInstanceCount());
	kprintf("IOSKMapper count : %u, %u (sub maps)\n",
	    IOSKMapper::gMetaClass.getInstanceCount(),
	    IOSKRegionMapper::gMetaClass.getInstanceCount());
	kprintf("IOSKBuffer count : %u\n",
	    IOSKBuffer::gMetaClass.getInstanceCount());

	return 0;
}

#endif  /* DEVELOPMENT || DEBUG */

#if defined(__x86_64__)
const OSSymbol *
IOSKCopyKextIdentifierWithAddress( vm_address_t address )
{
	const OSSymbol * id = NULL;

	OSKext * kext = OSKext::lookupKextWithAddress(address);
	if (kext) {
		id = kext->getIdentifier();
		if (id) {
			id->retain();
		}
		kext->release();
	}
	return id;
}
#endif /* __x86_64__ */
