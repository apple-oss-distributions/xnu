/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
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

#ifndef _IOKIT_IONVRAM_H
#define _IOKIT_IONVRAM_H

#ifdef __cplusplus
#include <libkern/c++/OSPtr.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/nvram/IONVRAMController.h>
#endif /* __cplusplus */
#include <uuid/uuid.h>

enum NVRAMPartitionType {
	kIONVRAMPartitionTypeUnknown,
	kIONVRAMPartitionSystem,
	kIONVRAMPartitionCommon
};

enum IONVRAMVariableType {
	kOFVariableTypeBoolean = 1,
	kOFVariableTypeNumber,
	kOFVariableTypeString,
	kOFVariableTypeData
};

enum IONVRAMOperation {
	kIONVRAMOperationInit,
	kIONVRAMOperationRead,
	kIONVRAMOperationWrite,
	kIONVRAMOperationDelete,
	kIONVRAMOperationObliterate,
	kIONVRAMOperationReset
};

enum {
	// Deprecated but still used in AppleEFIRuntime for now
	kOFVariablePermRootOnly = 0,
	kOFVariablePermUserRead,
	kOFVariablePermUserWrite,
	kOFVariablePermKernelOnly
};

#ifdef __cplusplus

class IODTNVRAMVariables;
class IODTNVRAMDiags;

class IODTNVRAMFormatHandler
{
public:
	virtual
	~IODTNVRAMFormatHandler();
	virtual IOReturn setVariable(const uuid_t *varGuid, const char *variableName, OSObject *object) = 0;
	virtual bool setController(IONVRAMController *_nvramController) = 0;
	virtual bool sync(void) = 0;
	virtual uint32_t getGeneration(void) const = 0;
	virtual uint32_t getVersion(void) const = 0;
	virtual uint32_t getSystemUsed(void) const = 0;
	virtual uint32_t getCommonUsed(void) const = 0;
};

class IODTNVRAM : public IOService
{
	OSDeclareDefaultStructors(IODTNVRAM);

private:
	friend class IODTNVRAMVariables;
	friend class IONVRAMCHRPHandler;
	friend class IONVRAMV3Handler;

	IODTNVRAMDiags         *_diags;
	IODTNVRAMFormatHandler *_format;

	IORWLock               *_variableLock;
	IOLock                 *_controllerLock;

	IODTNVRAMVariables     *_commonService;
	IODTNVRAMVariables     *_systemService;

	OSPtr<OSDictionary>    _commonDict;
	OSPtr<OSDictionary>    _systemDict;

	SInt32                 _lastDeviceSync;
	bool                   _freshInterval;

	void initImageFormat(void);

	uint32_t getNVRAMSize(void);

	NVRAMPartitionType getDictionaryType(const OSDictionary *dict) const;
	IOReturn chooseDictionary(IONVRAMOperation operation, const uuid_t *varGuid,
	    const char *variableName, OSDictionary **dict) const;
	IOReturn flushDict(const uuid_t *guid, IONVRAMOperation op);
	bool handleSpecialVariables(const char *name, const uuid_t *guid, const OSObject *obj, IOReturn *error);

	IOReturn setPropertyInternal(const OSSymbol *aKey, OSObject *anObject);
	IOReturn removePropertyInternal(const OSSymbol *aKey);
	OSSharedPtr<OSObject> copyPropertyWithGUIDAndName(const uuid_t *guid, const char *name) const;
	IOReturn removePropertyWithGUIDAndName(const uuid_t *guid, const char *name);
	IOReturn setPropertyWithGUIDAndName(const uuid_t *guid, const char *name, OSObject *anObject);

	void syncInternal(bool rateLimit);
	bool safeToSync(void);

public:
	virtual bool init(IORegistryEntry *old, const IORegistryPlane *plane) APPLE_KEXT_OVERRIDE;
	virtual bool start(IOService * provider) APPLE_KEXT_OVERRIDE;

	virtual void registerNVRAMController(IONVRAMController *controller);

	virtual void sync(void);

	virtual bool serializeProperties(OSSerialize *s) const APPLE_KEXT_OVERRIDE;
	virtual OSPtr<OSObject> copyProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSPtr<OSObject> copyProperty(const char *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSObject *getProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSObject *getProperty(const char *aKey) const APPLE_KEXT_OVERRIDE;
	virtual bool setProperty(const OSSymbol *aKey, OSObject *anObject) APPLE_KEXT_OVERRIDE;
	virtual void removeProperty(const OSSymbol *aKey) APPLE_KEXT_OVERRIDE;
	virtual IOReturn setProperties(OSObject *properties) APPLE_KEXT_OVERRIDE;

	virtual IOReturn readXPRAM(IOByteCount offset, uint8_t *buffer,
	    IOByteCount length);
	virtual IOReturn writeXPRAM(IOByteCount offset, uint8_t *buffer,
	    IOByteCount length);

	virtual IOReturn readNVRAMProperty(IORegistryEntry *entry,
	    const OSSymbol **name,
	    OSData **value);
	virtual IOReturn writeNVRAMProperty(IORegistryEntry *entry,
	    const OSSymbol *name,
	    OSData *value);

	virtual OSDictionary *getNVRAMPartitions(void);

	virtual IOReturn readNVRAMPartition(const OSSymbol *partitionID,
	    IOByteCount offset, uint8_t *buffer,
	    IOByteCount length);

	virtual IOReturn writeNVRAMPartition(const OSSymbol *partitionID,
	    IOByteCount offset, uint8_t *buffer,
	    IOByteCount length);

	virtual IOByteCount savePanicInfo(uint8_t *buffer, IOByteCount length);
};

#endif /* __cplusplus */

#endif /* !_IOKIT_IONVRAM_H */
