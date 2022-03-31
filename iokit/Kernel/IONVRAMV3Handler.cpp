/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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

#include <libkern/libkern.h>

#define VARIABLE_STORE_SIGNATURE         'NVV3'

// Variable Store Version
#define VARIABLE_STORE_VERSION           0x1

#define VARIABLE_DATA                    0x55AA
#define INVALIDATED_VARIABLE_DATA        0x0000

// Variable State flags
#define VAR_IN_DELETED_TRANSITION     0xFE  // Variable is in obsolete transistion
#define VAR_DELETED                   0xFD  // Variable is obsolete
#define VAR_INACTIVE                  0xFB  // Variable is inactive due to failing CRC
#define VAR_ADDED                     0x7F  // Variable has been completely added

// No changes needed on save
#define VAR_NEW_STATE_NONE            0x01
// Remove existing entry on save
#define VAR_NEW_STATE_REMOVE          0x02
// Add new value on save, mark previous as inactive
#define VAR_NEW_STATE_APPEND          0x03
// Originally read from the proxy data and needs to be syncd
// with the backing store when available
#define VAR_NEW_STATE_INIT            0x04

#pragma pack(1)
struct v3_store_header {
	uint32_t     name;
	uint32_t     size;
	uint32_t     generation;
	uint8_t      state;
	uint8_t      flags;
	uint8_t      version;
	uint8_t      reserved1;
	uint32_t     system_size;
	uint32_t     common_size;
};

struct v3_var_header {
	uint16_t     startId;
	uint8_t      state;
	uint8_t      reserved;
	uint32_t     attributes;
	uint32_t     nameSize;
	uint32_t     dataSize;
	uuid_t       guid;
	uint32_t     crc;
	uint8_t      name_data_buf[];
};
#pragma pack()

struct nvram_v3_var_entry {
	uint8_t                new_state;
	size_t                 existing_offset;
	struct v3_var_header   header;
};

static size_t
nvram_v3_var_entry_size(const struct v3_var_header *header)
{
	return sizeof(struct nvram_v3_var_entry) + header->nameSize + header->dataSize;
}

static size_t
variable_length(const struct v3_var_header *header)
{
	return sizeof(struct v3_var_header) + header->nameSize + header->dataSize;
}

static bool
valid_store_header(const struct v3_store_header *header)
{
	return (header->name == VARIABLE_STORE_SIGNATURE) && (header->version == VARIABLE_STORE_VERSION);
}

static bool
valid_variable_header(const struct v3_var_header *header, size_t buf_len)
{
	return (buf_len > sizeof(struct v3_var_header)) &&
	       (header->startId == VARIABLE_DATA) &&
	       (variable_length(header) <= buf_len);
}

static uint32_t
find_active_var_in_image(const struct v3_var_header *var, const uint8_t *image, uint32_t len)
{
	uint32_t offset = sizeof(struct v3_store_header);
	const struct v3_var_header *store_var;
	uint32_t var_offset = 0;

	while ((offset + sizeof(struct v3_var_header) < len)) {
		store_var = (const struct v3_var_header *)(image + offset);

		if (valid_variable_header(store_var, len - offset)) {
			if ((store_var->state == VAR_ADDED) &&
			    (var->nameSize == store_var->nameSize) &&
			    (memcmp(var->name_data_buf, store_var->name_data_buf, var->nameSize) == 0)) {
				var_offset = offset;
				break;
			}
		} else {
			break;
		}

		offset += variable_length(store_var);
	}

	return var_offset;
}

static uint32_t
find_current_offset_in_image(const uint8_t *image, uint32_t len)
{
	uint32_t offset = 0;
	uint32_t inner_offset = 0;

	if (valid_store_header((const struct v3_store_header *)(image + offset))) {
		DEBUG_INFO("valid store header @ %#x\n", offset);
		offset += sizeof(struct v3_store_header);
	}

	while (offset < len) {
		if (valid_variable_header((const struct v3_var_header *)(image + offset), len - offset)) {
			DEBUG_INFO("valid variable header @ %#x\n", offset);
			offset += variable_length((const struct v3_var_header *)(image + offset));
		} else {
			break;
		}
	}

	while (offset < len) {
		if (image[offset] == 0xFF) {
			DEBUG_INFO("scanning for clear memory @ %#x\n", offset);

			inner_offset = offset;

			while ((inner_offset < len) && (image[inner_offset] == 0xFF)) {
				inner_offset++;
			}

			if (inner_offset == len) {
				DEBUG_INFO("found start of clear mem @ %#x\n", offset);
				return offset;
			} else {
				DEBUG_ERROR("ERROR!!!!! found non-clear byte @ %#x\n", offset);
				offset = inner_offset;
			}
		}
		offset++;
	}

	return 0;
}

class IONVRAMV3Handler : public IODTNVRAMFormatHandler
{
private:
	IONVRAMController            *_nvramController;
	IODTNVRAM                    *_provider;

	bool                         _newData;

	uint32_t                     _generation;

	uint8_t                      *_nvramImage;
	uint32_t                     _nvramSize;

	OSSharedPtr<OSDictionary>    &_commonDict;
	OSSharedPtr<OSDictionary>    &_systemDict;

	uint32_t                     _commonSize;
	uint32_t                     _systemSize;

	uint32_t                     _commonUsed;
	uint32_t                     _systemUsed;

	uint32_t                     _currentOffset;

	OSSharedPtr<OSArray>         _varEntries;

	IOReturn unserializeImage(const uint8_t *image, IOByteCount length);

	IOReturn reclaim(void);

	static bool convertObjectToProp(uint8_t *buffer, uint32_t *length, const char *propSymbol, OSObject *propObject);
	static bool convertPropToObject(const uint8_t *propName, uint32_t propNameLength, const uint8_t *propData, uint32_t propDataLength,
	    OSSharedPtr<const OSSymbol>& propSymbol, OSSharedPtr<OSObject>& propObject);

	IOReturn syncInternal(void);

public:
	virtual
	~IONVRAMV3Handler() APPLE_KEXT_OVERRIDE;
	IONVRAMV3Handler(OSSharedPtr<OSDictionary> &commonDict, OSSharedPtr<OSDictionary> &systemDict);

	static bool isValidImage(const uint8_t *image, IOByteCount length);

	static  IONVRAMV3Handler *init(IODTNVRAM *provider, const uint8_t *image, IOByteCount length,
	    OSSharedPtr<OSDictionary> &commonDict, OSSharedPtr<OSDictionary> &systemDict);

	virtual IOReturn setVariable(const uuid_t *varGuid, const char *variableName, OSObject *object) APPLE_KEXT_OVERRIDE;
	virtual bool     setController(IONVRAMController *controller) APPLE_KEXT_OVERRIDE;
	virtual bool     sync(void) APPLE_KEXT_OVERRIDE;
	virtual uint32_t getGeneration(void) const APPLE_KEXT_OVERRIDE;
	virtual uint32_t getVersion(void) const APPLE_KEXT_OVERRIDE;
	virtual uint32_t getSystemUsed(void) const APPLE_KEXT_OVERRIDE;
	virtual uint32_t getCommonUsed(void) const APPLE_KEXT_OVERRIDE;
};

IONVRAMV3Handler::~IONVRAMV3Handler()
{
}

IONVRAMV3Handler::IONVRAMV3Handler(OSSharedPtr<OSDictionary> &commonDict, OSSharedPtr<OSDictionary> &systemDict) :
	_commonDict(commonDict),
	_systemDict(systemDict)
{
}

bool
IONVRAMV3Handler::isValidImage(const uint8_t *image, IOByteCount length)
{
	const struct v3_store_header *header = (const struct v3_store_header *)image;

	if ((header == nullptr) || (length < sizeof(*header))) {
		return false;
	}

	return valid_store_header(header);
}

IONVRAMV3Handler*
IONVRAMV3Handler::init(IODTNVRAM *provider, const uint8_t *image, IOByteCount length,
    OSSharedPtr<OSDictionary> &commonDict, OSSharedPtr<OSDictionary> &systemDict)
{
	IONVRAMV3Handler *handler = new IONVRAMV3Handler(commonDict, systemDict);

	handler->_provider = provider;

	if ((image != nullptr) && (length != 0)) {
		if (handler->unserializeImage(image, length) != kIOReturnSuccess) {
			DEBUG_ERROR("Unable to unserialize image, len=%#x\n", (unsigned int)length);
		}
	}

	return handler;
}

IOReturn
IONVRAMV3Handler::unserializeImage(const uint8_t *image, IOByteCount length)
{
	OSSharedPtr<const OSSymbol>  propSymbol;
	OSSharedPtr<OSObject>        propObject;
	OSSharedPtr<OSData>          entryContainer;
	const struct v3_store_header *storeHeader;
	IOReturn                     ret = kIOReturnSuccess;
	struct nvram_v3_var_entry    *v3Entry;
	const struct v3_var_header   *header;
	size_t                       offset = sizeof(struct v3_store_header);
	uint32_t                     crc;
	unsigned int                 i;
	bool                         system;
	OSDictionary                 *dict;

	require(isValidImage(image, length), exit);

	storeHeader = (const struct v3_store_header *)image;
	require_action(storeHeader->size == (uint32_t)length, exit,
	    DEBUG_ERROR("Image size %#x != header size %#x\n", (unsigned int)length, storeHeader->size));

	_generation = storeHeader->generation;
	_systemSize = storeHeader->system_size;
	_commonSize = storeHeader->common_size - sizeof(struct v3_store_header);

	_systemUsed = 0;
	_commonUsed = 0;

	if (_nvramImage) {
		IOFreeData(_nvramImage, _nvramSize);
	}

	_varEntries.reset();
	_varEntries = OSArray::withCapacity(40);

	_nvramImage = IONewData(uint8_t, length);
	_nvramSize = (uint32_t)length;
	bcopy(image, _nvramImage, _nvramSize);

	if (_systemSize) {
		_systemDict = OSDictionary::withCapacity(1);
	}

	if (_commonSize) {
		_commonDict = OSDictionary::withCapacity(1);
	}

	while ((offset + sizeof(struct v3_var_header)) < length) {
		header = (const struct v3_var_header *)(image + offset);

		for (i = 0; i < sizeof(struct v3_var_header); i++) {
			if ((image[offset + i] != 0) && (image[offset + i] != 0xFF)) {
				break;
			}
		}

		if (i == sizeof(struct v3_var_header)) {
			DEBUG_INFO("No more variables after offset %#lx\n", offset);
			break;
		}

		if (!valid_variable_header(header, length - offset)) {
			DEBUG_ERROR("invalid header @ %#lx\n", offset);
			offset += sizeof(struct v3_var_header);
			continue;
		}

		if (header->state != VAR_ADDED) {
			DEBUG_INFO("inactive var @ %#lx\n", offset);
			goto skip;
		}

		crc = crc32(0, header->name_data_buf + header->nameSize, header->dataSize);

		if (crc != header->crc) {
			DEBUG_ERROR("invalid crc @ %#lx, calculated=%#x, read=%#x\n", offset, crc, header->crc);
			goto skip;
		}

		DEBUG_INFO("entry: %s, size=%#zx, existing_offset=%#zx\n", header->name_data_buf, nvram_v3_var_entry_size(header), offset);
		v3Entry = (struct nvram_v3_var_entry *)IOMallocZeroData(nvram_v3_var_entry_size(header));
		__nochk_memcpy(&v3Entry->header, _nvramImage + offset, variable_length(header));

		// It is assumed that the initial image being unserialized here is going to be the proxy data from EDT and not the image
		// read from the controller, which for various reasons due to the setting of states and saves from iBoot, can be
		// different. We will have an initial existing_offset of 0 with VAR_NEW_STATE_INIT here and once the controller is set we will read
		// out the image there and merge our current data with the actual store
		v3Entry->existing_offset = 0;
		v3Entry->new_state = VAR_NEW_STATE_INIT;

		entryContainer = OSData::withBytes(v3Entry, (uint32_t)nvram_v3_var_entry_size(header));
		_varEntries->setObject(entryContainer.get());

		system = (_systemSize != 0) && (uuid_compare(v3Entry->header.guid, gAppleSystemVariableGuid) == 0);
		if (system) {
			dict = _systemDict.get();
			_systemUsed += variable_length(header);
		} else {
			dict = _commonDict.get();
			_commonUsed += variable_length(header);
		}

		if (convertPropToObject(v3Entry->header.name_data_buf, v3Entry->header.nameSize,
		    v3Entry->header.name_data_buf + v3Entry->header.nameSize, v3Entry->header.dataSize,
		    propSymbol, propObject)) {
			DEBUG_INFO("adding %s, dataLength=%u, system=%d\n",
			    propSymbol->getCStringNoCopy(), v3Entry->header.dataSize, system);

			dict->setObject(propSymbol.get(), propObject.get());

			if (_provider->_diags) {
				_provider->_diags->logVariable(_provider->getDictionaryType(dict),
				    kIONVRAMOperationInit, propSymbol.get()->getCStringNoCopy(),
				    (void *)(uintptr_t)(header->name_data_buf + header->nameSize));
			}
		}
		IOFreeData(v3Entry, nvram_v3_var_entry_size(header));
skip:
		offset += variable_length(header);
	}

	_currentOffset = (uint32_t)offset;

	DEBUG_ALWAYS("_commonSize %#x, _systemSize %#x, _currentOffset %#x\n", _commonSize, _systemSize, _currentOffset);
exit:
	_newData = true;

	if (_provider->_diags) {
		OSSharedPtr<OSNumber> val = OSNumber::withNumber(getSystemUsed(), 32);
		_provider->_diags->setProperty(kNVRAMSystemUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMSystemUsedKey, getSystemUsed());

		val = OSNumber::withNumber(getCommonUsed(), 32);
		_provider->_diags->setProperty(kNVRAMCommonUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMCommonUsedKey, getCommonUsed());
	}

	return ret;
}

IOReturn
IONVRAMV3Handler::setVariable(const uuid_t *varGuid, const char *variableName, OSObject *object)
{
	struct nvram_v3_var_entry *v3Entry = nullptr;
	struct nvram_v3_var_entry *newV3Entry;
	OSData                    *entryContainer = nullptr;
	OSSharedPtr<OSData>       newContainer;
	bool                      unset = (object == nullptr);
	bool                      system = false;
	IOReturn                  ret = kIOReturnSuccess;
	size_t                    entryNameLen = strlen(variableName) + 1;
	unsigned int              existingEntryIndex;
	uint32_t                  dataSize = 0;
	size_t                    existingEntrySize = 0;
	size_t                    newEntrySize;

	if (_systemSize != 0) {
		if ((uuid_compare(v3Entry->header.guid, gAppleSystemVariableGuid) == 0) || variableInAllowList(variableName)) {
			system = true;
		}
	}

	DEBUG_INFO("setting %s, system=%d\n", variableName, system);

	for (existingEntryIndex = 0; existingEntryIndex < _varEntries->getCount(); existingEntryIndex++) {
		entryContainer = (OSDynamicCast(OSData, _varEntries->getObject(existingEntryIndex)));
		v3Entry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();

		if ((v3Entry->header.nameSize == entryNameLen) &&
		    (memcmp(v3Entry->header.name_data_buf, variableName, entryNameLen) == 0) &&
		    (uuid_compare(*varGuid, v3Entry->header.guid) == 0)) {
			DEBUG_INFO("found existing entry for %s, unset=%d @ %#lx\n", variableName, unset, v3Entry->existing_offset);
			existingEntrySize = nvram_v3_var_entry_size(&v3Entry->header);
			break;
		}

		v3Entry = nullptr;
	}

	if (unset == true) {
		if (v3Entry == NULL) {
			DEBUG_INFO("unset %s but no entry\n", variableName);
		} else if (v3Entry->new_state == VAR_NEW_STATE_REMOVE) {
			DEBUG_INFO("entry %s already marked for remove\n", variableName);
		} else {
			DEBUG_INFO("marking entry %s for remove\n", variableName);

			v3Entry->new_state = VAR_NEW_STATE_REMOVE;

			if (system) {
				_provider->_systemDict->removeObject(variableName);

				if (_systemUsed < variable_length(&v3Entry->header)) {
					panic("Invalid _systemUsed size\n");
				}

				_systemUsed -= variable_length(&v3Entry->header);
			} else {
				_provider->_commonDict->removeObject(variableName);

				if (_commonUsed < variable_length(&v3Entry->header)) {
					panic("Invalid _commonUsed size\n");
				}
				_commonUsed -= variable_length(&v3Entry->header);
			}

			if (_provider->_diags) {
				_provider->_diags->logVariable(getPartitionTypeForGUID(varGuid), kIONVRAMOperationDelete, variableName, nullptr);
			}
		}
	} else {
		convertObjectToProp(nullptr, &dataSize, variableName, object);

		newEntrySize = sizeof(struct nvram_v3_var_entry) + entryNameLen + dataSize;

		if (system && (_systemUsed - existingEntrySize + newEntrySize > _systemSize)) {
			DEBUG_ERROR("system region full\n");
			ret = kIOReturnNoSpace;
			goto exit;
		} else if (!system && (_commonUsed - existingEntrySize + newEntrySize > _commonSize)) {
			DEBUG_ERROR("common region full\n");
			ret = kIOReturnNoSpace;
			goto exit;
		}

		DEBUG_INFO("creating new entry for %s, dataSize=%#x\n", variableName, dataSize);
		newV3Entry = (struct nvram_v3_var_entry *)IOMallocZeroData(newEntrySize);

		memcpy(newV3Entry->header.name_data_buf, variableName, entryNameLen);
		convertObjectToProp(newV3Entry->header.name_data_buf + entryNameLen, &dataSize, variableName, object);

		newV3Entry->header.startId = VARIABLE_DATA;
		newV3Entry->header.nameSize = (uint32_t)entryNameLen;
		newV3Entry->header.dataSize = dataSize;
		newV3Entry->header.crc = crc32(0, newV3Entry->header.name_data_buf + entryNameLen, dataSize);

		if (system) {
			memcpy(newV3Entry->header.guid, varGuid, sizeof(*varGuid));
		} else {
			memcpy(newV3Entry->header.guid, gAppleNVRAMGuid, sizeof(gAppleNVRAMGuid));
		}

		newV3Entry->new_state = VAR_NEW_STATE_APPEND;

		newEntrySize = nvram_v3_var_entry_size(&newV3Entry->header);

		if (v3Entry) {
			newV3Entry->existing_offset = v3Entry->existing_offset;
			newV3Entry->header.state = v3Entry->header.state;
			newV3Entry->header.attributes = v3Entry->header.attributes;

			newContainer = OSData::withBytes(newV3Entry, (uint32_t)newEntrySize);
			_varEntries->replaceObject(existingEntryIndex, newContainer.get());
		} else {
			newContainer = OSData::withBytes(newV3Entry, (uint32_t)newEntrySize);
			_varEntries->setObject(newContainer.get());
		}

		if (system) {
			_systemUsed = _systemUsed + (uint32_t)newEntrySize - (uint32_t)existingEntrySize;
			_provider->_systemDict->setObject(variableName, object);
		} else {
			_commonUsed = _commonUsed + (uint32_t)newEntrySize - (uint32_t)existingEntrySize;
			_provider->_commonDict->setObject(variableName, object);
		}

		if (_provider->_diags) {
			_provider->_diags->logVariable(getPartitionTypeForGUID(varGuid), kIONVRAMOperationWrite, variableName, (void *)(uintptr_t)dataSize);
		}

		IOFreeData(newV3Entry, newEntrySize);
	}

exit:
	_newData = true;

	if (_provider->_diags) {
		OSSharedPtr<OSNumber> val = OSNumber::withNumber(getSystemUsed(), 32);
		_provider->_diags->setProperty(kNVRAMSystemUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMSystemUsedKey, getSystemUsed());

		val = OSNumber::withNumber(getCommonUsed(), 32);
		_provider->_diags->setProperty(kNVRAMCommonUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMCommonUsedKey, getCommonUsed());
	}

	return ret;
}

bool
IONVRAMV3Handler::setController(IONVRAMController *controller)
{
	IOReturn                     ret = kIOReturnSuccess;
	uint8_t                      *controllerImage;
	struct nvram_v3_var_entry    *v3Entry;
	const struct v3_store_header *storeHeader;
	const struct v3_var_header   *storeVar;
	OSData                       *entryContainer;

	if (_nvramController == NULL) {
		_nvramController = controller;
	}

	require(_nvramSize != 0, exit);

	controllerImage = (uint8_t *)IOMallocData(_nvramSize);
	_nvramController->read(0, controllerImage, _nvramSize);

	if (isValidImage(controllerImage, _nvramSize)) {
		DEBUG_INFO("valid image found\n");

		storeHeader = (const struct v3_store_header *)controllerImage;

		_generation = storeHeader->generation;

		// We must sync any existing variables offset on the controller image with our internal representation
		// All variables added from the EDT proxy data initial unserialize are still in a VAR_NEW_STATE_INIT
		// If we find an existing entry and the data is still the same we record the existing offset and mark it
		// as VAR_NEW_STATE_NONE meaning no action needed
		// Otherwise if the data is different or it is not found on the controller image we mark it as VAR_NEW_STATE_APPEND
		// which will have us invalidate the existing entry if there is one and append it on the next save
		for (unsigned int i = 0; i < _varEntries->getCount(); i++) {
			entryContainer = (OSDynamicCast(OSData, _varEntries->getObject(i)));
			v3Entry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();

			if (v3Entry->new_state == VAR_NEW_STATE_INIT) {
				v3Entry->existing_offset = find_active_var_in_image(&v3Entry->header, controllerImage, _nvramSize);

				if (v3Entry->existing_offset == 0) {
					DEBUG_ERROR("%s is not in the NOR image\n", v3Entry->header.name_data_buf);
					if (v3Entry->header.dataSize == 0) {
						DEBUG_INFO("%s marked for remove\n", v3Entry->header.name_data_buf);
						// Doesn't exist in the store and with a 0 dataSize is pending remove
						v3Entry->new_state = VAR_NEW_STATE_REMOVE;
					} else {
						DEBUG_INFO("%s marked for append\n", v3Entry->header.name_data_buf);
						// Doesn't exist in the store, just append it on next sync
						v3Entry->new_state = VAR_NEW_STATE_APPEND;
					}
				} else {
					DEBUG_INFO("Found offset for %s @ %#zx\n", v3Entry->header.name_data_buf, v3Entry->existing_offset);
					storeVar = (const struct v3_var_header *)&controllerImage[v3Entry->existing_offset];

					if ((variable_length(&v3Entry->header) == variable_length(storeVar)) &&
					    (memcmp(v3Entry->header.name_data_buf, storeVar->name_data_buf, storeVar->nameSize + storeVar->dataSize) == 0)) {
						DEBUG_INFO("Store var for %s matches, marking new state none\n", v3Entry->header.name_data_buf);
						v3Entry->new_state = VAR_NEW_STATE_NONE;
					} else {
						DEBUG_INFO("Store var for %s differs, marking new state append\n", v3Entry->header.name_data_buf);
						v3Entry->new_state = VAR_NEW_STATE_APPEND;
					}
				}
			}
		}

		_currentOffset = find_current_offset_in_image(controllerImage, _nvramSize);
		DEBUG_INFO("New _currentOffset=%#x\n", _currentOffset);
	} else {
		DEBUG_ERROR("Invalid image found, issuing reclaim recovery\n");
		ret = reclaim();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reclaim recovery failed, invalid controller state!!! ret=%#x\n", ret));
	}

	IOFreeData(controllerImage, _nvramSize);

exit:
	return ret == kIOReturnSuccess;
}

IOReturn
IONVRAMV3Handler::reclaim(void)
{
	IOReturn ret;
	struct   v3_store_header newStoreHeader;
	struct   v3_var_header *varHeader;
	struct   nvram_v3_var_entry *varEntry;
	OSData   *entryContainer;
	size_t   new_bank_offset = sizeof(struct v3_store_header);

	DEBUG_INFO("called\n");

	ret = _nvramController->nextBank();
	verify_noerr_action(ret, DEBUG_ERROR("Bank shift not triggered\n"));

	for (unsigned int i = 0; i < _varEntries->getCount(); i++) {
		entryContainer = OSDynamicCast(OSData, _varEntries->getObject(i));
		varEntry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();
		varHeader = &varEntry->header;

		DEBUG_INFO("entry %u %s, new_state=%#x, e_offset=%#lx, state=%#x\n",
		    i, varEntry->header.name_data_buf, varEntry->new_state, varEntry->existing_offset, varHeader->state);

		if (varEntry->new_state == VAR_NEW_STATE_NONE) {
			ret = _nvramController->write(new_bank_offset, (uint8_t *)varHeader, variable_length(varHeader));
			require_noerr_action(ret, exit, DEBUG_ERROR("var write failed, ret=%08x\n", ret));

			varEntry->existing_offset = new_bank_offset;
			new_bank_offset += variable_length(varHeader);
		} else {
			// Set existing offset to 0 so that they will either be appended
			// or any remaining removals will be dropped
			varEntry->existing_offset = 0;
		}
	}

	memcpy(&newStoreHeader, _nvramImage, sizeof(newStoreHeader));

	_generation += 1;

	newStoreHeader.generation = _generation;

	ret = _nvramController->write(0, (uint8_t *)&newStoreHeader, sizeof(newStoreHeader));
	require_noerr_action(ret, exit, DEBUG_ERROR("store header write failed, ret=%08x\n", ret));

	_currentOffset = (uint32_t)new_bank_offset;

	DEBUG_INFO("Reclaim complete, _generation=%u, _currentOffset=%#x\n", _generation, _currentOffset);

exit:
	return ret;
}

IOReturn
IONVRAMV3Handler::syncInternal(void)
{
	IOReturn             ret = kIOReturnSuccess;
	size_t               varEndOffset;
	size_t               varStartOffset;
	struct               nvram_v3_var_entry *varEntry;
	struct               v3_var_header *varHeader;
	OSData               *entryContainer;
	OSSharedPtr<OSArray> remainingEntries;

	require_action(_nvramController != nullptr, exit, DEBUG_INFO("No _nvramController\n"));
	require_action(_newData == true, exit, DEBUG_INFO("No _newData to sync\n"));
	require_action(_nvramSize != 0, exit, DEBUG_INFO("No nvram size info\n"));

	DEBUG_INFO("_varEntries->getCount()=%#x\n", _varEntries->getCount());

	remainingEntries = OSArray::withCapacity(_varEntries->getCapacity());

	for (unsigned int i = 0; i < _varEntries->getCount(); i++) {
		size_t space_needed = 0;
		uint8_t state;

		entryContainer = OSDynamicCast(OSData, _varEntries->getObject(i));
		varEntry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();
		varHeader = &varEntry->header;

		DEBUG_INFO("%s new_state=%d, e_off=%#lx, c_off=%#x, uuid=%x%x, nameSize=%#x, dataSize=%#x\n",
		    varEntry->header.name_data_buf,
		    varEntry->new_state, varEntry->existing_offset, _currentOffset,
		    varHeader->guid[0], varHeader->guid[1],
		    varHeader->nameSize, varHeader->dataSize);

		if (varEntry->new_state == VAR_NEW_STATE_APPEND) {
			space_needed = variable_length(varHeader);

			// reclaim if needed
			if ((_currentOffset + space_needed) > _nvramSize) {
				ret = reclaim();
				require_noerr_action(ret, exit, DEBUG_ERROR("reclaim fail, ret=%#x\n", ret));

				// Check after reclaim...
				if ((_currentOffset + space_needed) > _nvramSize) {
					DEBUG_ERROR("nvram full!\n");
					goto exit;
				}

				DEBUG_INFO("%s AFTER reclaim new_state=%d, e_off=%#lx, c_off=%#x, uuid=%x%x, nameSize=%#x, dataSize=%#x\n",
				    varEntry->header.name_data_buf,
				    varEntry->new_state, varEntry->existing_offset, _currentOffset,
				    varHeader->guid[0], varHeader->guid[1],
				    varHeader->nameSize, varHeader->dataSize);
			}

			if (varEntry->existing_offset) {
				// Mark existing entry as VAR_IN_DELETED_TRANSITION
				state = varHeader->state & VAR_IN_DELETED_TRANSITION;
				DEBUG_INFO("invalidating with state=%#x\n", state);

				ret = _nvramController->write(varEntry->existing_offset + offsetof(struct v3_var_header, state), &state, sizeof(state));
				require_noerr_action(ret, exit, DEBUG_ERROR("new state w fail, ret=%#x\n", ret));
			}

			varStartOffset = _currentOffset;
			varEndOffset = _currentOffset;

			// Append new entry as VAR_ADDED
			varHeader->state = VAR_ADDED;

			ret = _nvramController->write(varStartOffset, (uint8_t *)varHeader, variable_length(varHeader));
			require_noerr_action(ret, exit, DEBUG_ERROR("variable write fail, ret=%#x\n", ret); );

			varEndOffset += variable_length(varHeader);

			if (varEntry->existing_offset) {
				// Mark existing entry as VAR_DELETED
				state = varHeader->state & VAR_DELETED & VAR_IN_DELETED_TRANSITION;

				ret = _nvramController->write(varEntry->existing_offset + offsetof(struct v3_var_header, state), &state, sizeof(state));
				require_noerr_action(ret, exit, DEBUG_ERROR("existing state w fail, ret=%#x\n", ret));
			}

			varEntry->existing_offset = varStartOffset;
			varEntry->new_state = VAR_NEW_STATE_NONE;

			_currentOffset = (uint32_t)varEndOffset;

			remainingEntries->setObject(entryContainer);
		} else if (varEntry->new_state == VAR_NEW_STATE_REMOVE) {
			if (varEntry->existing_offset) {
				DEBUG_INFO("marking entry at offset %#lx deleted\n", varEntry->existing_offset);

				// Mark existing entry as VAR_IN_DELETED_TRANSITION
				state = varHeader->state & VAR_DELETED & VAR_IN_DELETED_TRANSITION;

				ret = _nvramController->write(varEntry->existing_offset + offsetof(struct v3_var_header, state), &state, sizeof(state));
				require_noerr_action(ret, exit, DEBUG_ERROR("existing state w fail, ret=%#x\n", ret));
			} else {
				DEBUG_INFO("No existing, removing\n");
			}

			// not re-added to remainingEntries
		} else {
			DEBUG_INFO("skipping\n");
			remainingEntries->setObject(entryContainer);
		}
	}

	_varEntries.reset(remainingEntries.get(), OSRetain);

	_newData = false;

exit:
	return ret;
}

bool
IONVRAMV3Handler::sync(void)
{
	IOReturn ret;

	ret = syncInternal();

	if (ret != kIOReturnSuccess) {
		ret = reclaim();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reclaim recovery failed, ret=%#x", ret));
	}

exit:
	return ret == kIOReturnSuccess;
}

uint32_t
IONVRAMV3Handler::getGeneration(void) const
{
	return _generation;
}

uint32_t
IONVRAMV3Handler::getVersion(void) const
{
	return kNVRAMVersion3;
}

uint32_t
IONVRAMV3Handler::getSystemUsed(void) const
{
	return _systemUsed;
}

uint32_t
IONVRAMV3Handler::getCommonUsed(void) const
{
	return _commonUsed;
}

bool
IONVRAMV3Handler::convertObjectToProp(uint8_t *buffer, uint32_t *length,
    const char *propName, OSObject *propObject)
{
	uint32_t             offset;
	IONVRAMVariableType  propType;
	OSBoolean            *tmpBoolean = nullptr;
	OSNumber             *tmpNumber = nullptr;
	OSString             *tmpString = nullptr;
	OSData               *tmpData = nullptr;

	propType = getVariableType(propName);

	// Get the size of the data.
	offset = 0;
	switch (propType) {
	case kOFVariableTypeBoolean:
		tmpBoolean = OSDynamicCast(OSBoolean, propObject);
		if (tmpBoolean != nullptr) {
			const char *bool_buf;
			if (tmpBoolean->getValue()) {
				bool_buf = "true";
			} else {
				bool_buf = "false";
			}

			offset = (uint32_t)strlen(bool_buf);

			if (buffer) {
				if (*length < offset) {
					return false;
				} else {
					memcpy(buffer, bool_buf, offset);
				}
			}
		}
		break;

	case kOFVariableTypeNumber:
		tmpNumber = OSDynamicCast(OSNumber, propObject);
		if (tmpNumber != nullptr) {
			char num_buf[12];
			char *end_buf = num_buf;
			uint32_t tmpValue = tmpNumber->unsigned32BitValue();
			if (tmpValue == 0xFFFFFFFF) {
				end_buf += snprintf(end_buf, sizeof(num_buf), "-1");
			} else if (tmpValue < 1000) {
				end_buf += snprintf(end_buf, sizeof(num_buf), "%d", (uint32_t)tmpValue);
			} else {
				end_buf += snprintf(end_buf, sizeof(num_buf), "%#x", (uint32_t)tmpValue);
			}

			offset = (uint32_t)(end_buf - num_buf);
			if (buffer) {
				if (*length < offset) {
					return false;
				} else {
					memcpy(buffer, num_buf, offset);
				}
			}
		}
		break;

	case kOFVariableTypeString:
		tmpString = OSDynamicCast(OSString, propObject);
		if (tmpString != nullptr) {
			offset = tmpString->getLength();

			if (buffer) {
				if (*length < offset) {
					return false;
				} else {
					bcopy(tmpString->getCStringNoCopy(), buffer, offset);
				}
			}
		}
		break;

	case kOFVariableTypeData:
		tmpData = OSDynamicCast(OSData, propObject);
		if (tmpData != nullptr) {
			offset = tmpData->getLength();

			if (buffer) {
				if (*length < offset) {
					return false;
				} else {
					bcopy(tmpData->getBytesNoCopy(), buffer, offset);
				}
			}
		}
		break;

	default:
		return false;
	}

	*length = offset;

	return offset != 0;
}


bool
IONVRAMV3Handler::convertPropToObject(const uint8_t *propName, uint32_t propNameLength,
    const uint8_t *propData, uint32_t propDataLength,
    OSSharedPtr<const OSSymbol>& propSymbol,
    OSSharedPtr<OSObject>& propObject)
{
	OSSharedPtr<const OSSymbol> tmpSymbol;
	OSSharedPtr<OSNumber>       tmpNumber;
	OSSharedPtr<OSString>       tmpString;
	OSSharedPtr<OSObject>       tmpObject = nullptr;

	tmpSymbol = OSSymbol::withCString((const char *)propName);

	if (tmpSymbol == nullptr) {
		return false;
	}

	switch (getVariableType(tmpSymbol.get())) {
	case kOFVariableTypeBoolean:
		if (!strncmp("true", (const char *)propData, propDataLength)) {
			tmpObject.reset(kOSBooleanTrue, OSRetain);
		} else if (!strncmp("false", (const char *)propData, propDataLength)) {
			tmpObject.reset(kOSBooleanFalse, OSRetain);
		}
		break;

	case kOFVariableTypeNumber:
		tmpNumber = OSNumber::withNumber(strtol((const char *)propData, nullptr, 0), 32);
		if (tmpNumber != nullptr) {
			tmpObject = tmpNumber;
		}
		break;

	case kOFVariableTypeString:
		tmpString = OSString::withCString((const char *)propData, propDataLength);
		if (tmpString != nullptr) {
			tmpObject = tmpString;
		}
		break;

	case kOFVariableTypeData:
		tmpObject = OSData::withBytes(propData, propDataLength);
		break;

	default:
		break;
	}

	if (tmpObject == nullptr) {
		tmpSymbol.reset();
		return false;
	}

	propSymbol = tmpSymbol;
	propObject = tmpObject;

	return true;
}
