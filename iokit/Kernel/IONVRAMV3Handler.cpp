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
nvram_v3_var_container_size(const struct v3_var_header *header)
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
find_active_var_in_image(const struct v3_var_header *var, const uint8_t *image, uint32_t offset, uint32_t len)
{
	const struct v3_var_header *store_var;
	uint32_t var_offset = 0;

	while ((offset + sizeof(struct v3_var_header) < len)) {
		store_var = (const struct v3_var_header *)(image + offset);

		if (valid_variable_header(store_var, len - offset)) {
			if ((store_var->state == VAR_ADDED) &&
			    (uuid_compare(var->guid, store_var->guid) == 0) &&
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

static IOReturn
find_current_offset_in_image(const uint8_t *image, uint32_t len, uint32_t *newOffset)
{
	uint32_t offset = 0;
	uint32_t inner_offset = 0;

	if (valid_store_header((const struct v3_store_header *)(image + offset))) {
		DEBUG_INFO("valid store header @ %#x\n", offset);
		offset += sizeof(struct v3_store_header);
	}

	while (offset < len) {
		const struct v3_var_header *store_var = (const struct v3_var_header *)(image + offset);
		uuid_string_t uuidString;

		if (valid_variable_header(store_var, len - offset)) {
			uuid_unparse(store_var->guid, uuidString);
			DEBUG_INFO("Valid var @ %#08x, state=%#02x, length=%#08zx, %s:%s\n", offset, store_var->state,
			    variable_length(store_var), uuidString, store_var->name_data_buf);
			offset += variable_length(store_var);
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
				break;
			} else {
				DEBUG_ERROR("ERROR!!!!! found non-clear byte @ %#x\n", offset);
				return kIOReturnInvalid;
			}
		}
		offset++;
	}

	*newOffset = offset;

	return kIOReturnSuccess;
}

class IONVRAMV3Handler : public IODTNVRAMFormatHandler, IOTypedOperatorsMixin<IONVRAMV3Handler>
{
private:
	IONVRAMController            *_nvramController;
	IODTNVRAM                    *_provider;

	bool                         _newData;
	bool                         _resetData;
	bool                         _reload;

	bool                         _rawController;

	uint32_t                     _generation;

	uint8_t                      *_nvramImage;

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
	uint32_t findCurrentBank(void);

	static bool convertObjectToProp(uint8_t *buffer, uint32_t *length, const char *propSymbol, OSObject *propObject);
	static bool convertPropToObject(const uint8_t *propName, uint32_t propNameLength, const uint8_t *propData, uint32_t propDataLength,
	    OSSharedPtr<const OSSymbol>& propSymbol, OSSharedPtr<OSObject>& propObject);

	IOReturn reloadInternal(void);

	void setEntryForRemove(struct nvram_v3_var_entry *v3Entry, bool system);
	void findExistingEntry(const uuid_t *varGuid, const char *varName, struct nvram_v3_var_entry **existing, unsigned int *existingIndex);
	IOReturn syncRaw(void);
	IOReturn syncBlock(void);

public:
	virtual
	~IONVRAMV3Handler() APPLE_KEXT_OVERRIDE;
	IONVRAMV3Handler(OSSharedPtr<OSDictionary> &commonDict, OSSharedPtr<OSDictionary> &systemDict);

	static bool isValidImage(const uint8_t *image, IOByteCount length);

	static  IONVRAMV3Handler *init(IODTNVRAM *provider, const uint8_t *image, IOByteCount length,
	    OSSharedPtr<OSDictionary> &commonDict, OSSharedPtr<OSDictionary> &systemDict);

	virtual bool     getNVRAMProperties(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn setVariable(const uuid_t varGuid, const char *variableName, OSObject *object) APPLE_KEXT_OVERRIDE;
	virtual bool     setController(IONVRAMController *controller) APPLE_KEXT_OVERRIDE;
	virtual bool     sync(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn flush(const uuid_t guid, IONVRAMOperation op) APPLE_KEXT_OVERRIDE;
	virtual void     reload(void) APPLE_KEXT_OVERRIDE;
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
	OSSharedPtr<IORegistryEntry> entry;
	OSSharedPtr<OSObject>        prop;
	bool                         propertiesOk;

	IONVRAMV3Handler *handler = new IONVRAMV3Handler(commonDict, systemDict);

	handler->_provider = provider;

	propertiesOk = handler->getNVRAMProperties();
	require_action(propertiesOk, exit, DEBUG_ERROR("Unable to get NVRAM properties\n"));

	require_action(length == handler->_bankSize, exit, DEBUG_ERROR("length %#llx != _bankSize %#x\n", length, handler->_bankSize));

	if ((image != nullptr) && (length != 0)) {
		if (handler->unserializeImage(image, length) != kIOReturnSuccess) {
			DEBUG_ERROR("Unable to unserialize image, len=%#x\n", (unsigned int)length);
		}
	}

	return handler;

exit:
	delete handler;

	return nullptr;
}

bool
IONVRAMV3Handler::getNVRAMProperties()
{
	bool                         ok    = false;
	const char                   *rawControllerKey = "nvram-raw";
	OSSharedPtr<IORegistryEntry> entry;
	OSSharedPtr<OSObject>        prop;
	OSData *                     data;

	require_action(IODTNVRAMFormatHandler::getNVRAMProperties(), exit, DEBUG_ERROR("parent getNVRAMProperties failed\n"));

	entry = IORegistryEntry::fromPath("/chosen", gIODTPlane);
	require_action(entry, exit, DEBUG_ERROR("Unable to find chosen node\n"));

	prop = entry->copyProperty(rawControllerKey);
	require_action(prop != nullptr, exit, DEBUG_ERROR("No %s entry\n", rawControllerKey));

	data = OSDynamicCast(OSData, prop.get());
	require(data != nullptr, exit);

	_rawController = *((uint32_t*)data->getBytesNoCopy());
	DEBUG_INFO("_rawController = %d\n", _rawController);

	ok = true;

exit:
	return ok;
}

IOReturn
IONVRAMV3Handler::flush(const uuid_t guid, IONVRAMOperation op)
{
	IOReturn ret = kIOReturnSuccess;

	if ((_systemDict != nullptr) && (uuid_compare(guid, gAppleSystemVariableGuid) == 0)) {
		// System dictionary contains keys that are only using the system GUID
		const OSSymbol                    *key;
		OSSharedPtr<OSDictionary>         systemCopy;
		OSSharedPtr<OSCollectionIterator> iter;
		uuid_string_t                     uuidString;

		systemCopy = OSDictionary::withDictionary(_systemDict.get());
		iter = OSCollectionIterator::withCollection(systemCopy.get());
		if ((systemCopy == nullptr) || (iter == nullptr)) {
			ret = kIOReturnNoMemory;
			goto exit;
		}

		DEBUG_INFO("Flushing system region...\n");

		uuid_unparse(gAppleSystemVariableGuid, uuidString);
		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (verifyPermission(op, gAppleSystemVariableGuid, key)) {
				DEBUG_INFO("Clearing entry for %s:%s\n", uuidString, key->getCStringNoCopy());
				// Using setVariable() instead of setEntryForRemove() to handle any GUID logic
				// for system region
				setVariable(guid, key->getCStringNoCopy(), nullptr);
			} else {
				DEBUG_INFO("Keeping entry for %s:%s\n", uuidString, key->getCStringNoCopy());
			}
		}

		DEBUG_INFO("system dictionary flushed\n");
	} else if ((_commonDict != nullptr) && (uuid_compare(guid, gAppleNVRAMGuid) == 0)) {
		// Common dictionary contains everything that is not system this goes through our entire
		// store and clears anything that is permitted
		struct nvram_v3_var_entry *v3Entry = nullptr;
		OSData                    *entryContainer = nullptr;
		OSSharedPtr<OSDictionary> newCommonDict;
		uuid_string_t             uuidString;

		DEBUG_INFO("Flushing common region...\n");

		newCommonDict = OSDictionary::withCapacity(_commonDict->getCapacity());

		if (newCommonDict == nullptr) {
			ret = kIOReturnNoMemory;
			goto exit;
		}

		for (unsigned int index = 0; index < _varEntries->getCount(); index++) {
			entryContainer = (OSDynamicCast(OSData, _varEntries->getObject(index)));
			v3Entry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();
			const char *entryName = (const char *)v3Entry->header.name_data_buf;

			// Skip system variables if there is a system region
			if ((_systemSize != 0) && uuid_compare(v3Entry->header.guid, gAppleSystemVariableGuid) == 0) {
				continue;
			}

			uuid_unparse(v3Entry->header.guid, uuidString);
			if (verifyPermission(op, v3Entry->header.guid, entryName)) {
				DEBUG_INFO("Clearing entry for %s:%s\n", uuidString, entryName);
				setEntryForRemove(v3Entry, false);
			} else {
				DEBUG_INFO("Keeping entry for %s:%s\n", uuidString, entryName);
				newCommonDict->setObject(entryName, _commonDict->getObject(entryName));
			}
		}

		_commonDict = newCommonDict;
	}

	_newData = true;

	if (_provider->_diags) {
		OSSharedPtr<OSNumber> val = OSNumber::withNumber(getSystemUsed(), 32);
		_provider->_diags->setProperty(kNVRAMSystemUsedKey, val.get());

		val = OSNumber::withNumber(getCommonUsed(), 32);
		_provider->_diags->setProperty(kNVRAMCommonUsedKey, val.get());
	}

	DEBUG_INFO("_commonUsed %#x, _systemUsed %#x\n", _commonUsed, _systemUsed);

exit:
	return ret;
}

IOReturn
IONVRAMV3Handler::reloadInternal(void)
{
	IOReturn                     ret;
	uint32_t                     controllerBank;
	uint8_t                      *controllerImage;
	struct nvram_v3_var_entry    *v3Entry;
	const struct v3_store_header *storeHeader;
	const struct v3_var_header   *storeVar;
	OSData                       *entryContainer;

	controllerBank = findCurrentBank();

	if (_currentBank != controllerBank) {
		DEBUG_ERROR("_currentBank %#x != controllerBank %#x", _currentBank, controllerBank);
	}

	_currentBank = controllerBank;

	controllerImage = (uint8_t *)IOMallocData(_bankSize);

	_nvramController->select(_currentBank);
	_nvramController->read(0, controllerImage, _bankSize);

	require_action(isValidImage(controllerImage, _bankSize), exit,
	    (ret = kIOReturnInvalid, DEBUG_ERROR("Invalid image at bank %d\n", _currentBank)));

	DEBUG_INFO("valid image found\n");

	storeHeader = (const struct v3_store_header *)controllerImage;

	_generation = storeHeader->generation;

	// We must sync any existing variables offset on the controller image with our internal representation
	// If we find an existing entry and the data is still the same we record the existing offset and mark it
	// as VAR_NEW_STATE_NONE meaning no action needed
	// Otherwise if the data is different or it is not found on the controller image we mark it as VAR_NEW_STATE_APPEND
	// which will have us invalidate the existing entry if there is one and append it on the next save
	for (unsigned int i = 0; i < _varEntries->getCount(); i++) {
		uint32_t offset = sizeof(struct v3_store_header);
		uint32_t latestOffset;
		uint32_t prevOffset = 0;

		entryContainer = (OSDynamicCast(OSData, _varEntries->getObject(i)));
		v3Entry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();

		DEBUG_INFO("Looking for %s\n", v3Entry->header.name_data_buf);
		while ((latestOffset = find_active_var_in_image(&v3Entry->header, controllerImage, offset, _bankSize))) {
			DEBUG_INFO("Found offset for %s @ %#08x\n", v3Entry->header.name_data_buf, latestOffset);
			if (prevOffset) {
				DEBUG_INFO("Marking prev offset for %s at %#08x invalid\n", v3Entry->header.name_data_buf, offset);
				// Invalidate any previous duplicate entries in the store
				struct v3_var_header *prevVarHeader = (struct v3_var_header *)(controllerImage + prevOffset);
				uint8_t state = prevVarHeader->state & VAR_DELETED & VAR_IN_DELETED_TRANSITION;

				ret = _nvramController->write(prevOffset + offsetof(struct v3_var_header, state), &state, sizeof(state));
				require_noerr_action(ret, exit, DEBUG_ERROR("existing state w fail, ret=%#x\n", ret));
			}

			prevOffset = latestOffset;
			offset += latestOffset;
		}

		v3Entry->existing_offset = latestOffset ? latestOffset : prevOffset;
		DEBUG_INFO("Existing offset for %s at %#08zx\n", v3Entry->header.name_data_buf, v3Entry->existing_offset);

		if (v3Entry->existing_offset == 0) {
			DEBUG_ERROR("%s is not in the NOR image\n", v3Entry->header.name_data_buf);
			if (v3Entry->new_state != VAR_NEW_STATE_REMOVE) {
				DEBUG_INFO("%s marked for append\n", v3Entry->header.name_data_buf);
				// Doesn't exist in the store, just append it on next sync
				v3Entry->new_state = VAR_NEW_STATE_APPEND;
			}
		} else {
			DEBUG_INFO("Found offset for %s @ %#zx\n", v3Entry->header.name_data_buf, v3Entry->existing_offset);
			storeVar = (const struct v3_var_header *)&controllerImage[v3Entry->existing_offset];

			if (v3Entry->new_state != VAR_NEW_STATE_REMOVE) {
				// Verify that the existing data matches the store data
				if ((variable_length(&v3Entry->header) == variable_length(storeVar)) &&
				    (memcmp(v3Entry->header.name_data_buf, storeVar->name_data_buf, storeVar->nameSize + storeVar->dataSize) == 0)) {
					DEBUG_INFO("Store var data for %s matches, marking new state none\n", v3Entry->header.name_data_buf);
					v3Entry->new_state = VAR_NEW_STATE_NONE;
				} else {
					DEBUG_INFO("Store var data for %s differs, marking new state append\n", v3Entry->header.name_data_buf);
					v3Entry->new_state = VAR_NEW_STATE_APPEND;
				}
			} else {
				// Store has entry but it has been removed from our collection, keep it marked for delete but with updated
				// existing_offset for coherence
				DEBUG_INFO("Removing entry at %#08zx with next sync\n", v3Entry->existing_offset);
			}
		}
	}

	ret = find_current_offset_in_image(controllerImage, _bankSize, &_currentOffset);
	if (ret != kIOReturnSuccess) {
		DEBUG_ERROR("Unidentified bytes in image, reclaiming\n");
		ret = reclaim();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reclaim byte recovery failed, invalid controller state!!! ret=%#x\n", ret));
	}
	DEBUG_INFO("New _currentOffset=%#x\n", _currentOffset);

exit:
	IOFreeData(controllerImage, _bankSize);
	return ret;
}

void
IONVRAMV3Handler::reload(void)
{
	_reload = true;

	DEBUG_INFO("reload marked\n");
}

void
IONVRAMV3Handler::setEntryForRemove(struct nvram_v3_var_entry *v3Entry, bool system)
{
	const char * variableName;
	uint32_t variableSize;

	require_action(v3Entry != nullptr, exit, DEBUG_INFO("remove with no entry\n"));

	variableName = (const char *)v3Entry->header.name_data_buf;
	variableSize = (uint32_t)variable_length(&v3Entry->header);

	if (v3Entry->new_state == VAR_NEW_STATE_REMOVE) {
		DEBUG_INFO("entry %s already marked for remove\n", variableName);
	} else {
		DEBUG_INFO("marking entry %s for remove\n", variableName);

		v3Entry->new_state = VAR_NEW_STATE_REMOVE;

		if (system) {
			_provider->_systemDict->removeObject(variableName);

			if (_systemUsed < variableSize) {
				panic("Invalid _systemUsed size\n");
			}

			_systemUsed -= variableSize;
		} else {
			_provider->_commonDict->removeObject(variableName);

			if (_commonUsed < variableSize) {
				panic("Invalid _commonUsed size\n");
			}
			_commonUsed -= variableSize;
		}

		if (_provider->_diags) {
			_provider->_diags->logVariable(getPartitionTypeForGUID(v3Entry->header.guid),
			    kIONVRAMOperationDelete,
			    variableName,
			    nullptr);
		}
	}

exit:
	return;
}

void
IONVRAMV3Handler::findExistingEntry(const uuid_t *varGuid, const char *varName, struct nvram_v3_var_entry **existing, unsigned int *existingIndex)
{
	struct nvram_v3_var_entry *v3Entry = nullptr;
	OSData                    *entryContainer = nullptr;
	unsigned int              index = 0;
	uint32_t                  nameLen = (uint32_t)strlen(varName) + 1;

	for (index = 0; index < _varEntries->getCount(); index++) {
		entryContainer = (OSDynamicCast(OSData, _varEntries->getObject(index)));
		v3Entry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();

		if ((v3Entry->header.nameSize == nameLen) &&
		    (memcmp(v3Entry->header.name_data_buf, varName, nameLen) == 0)) {
			if (varGuid) {
				if (uuid_compare(*varGuid, v3Entry->header.guid) == 0) {
					uuid_string_t uuidString;
					uuid_unparse(*varGuid, uuidString);
					DEBUG_INFO("found existing entry for %s:%s, e_off=%#lx, len=%#lx, new_state=%#x\n", uuidString, varName,
					    v3Entry->existing_offset, variable_length(&v3Entry->header), v3Entry->new_state);
					break;
				}
			} else {
				DEBUG_INFO("found existing entry for %s, e_off=%#lx, len=%#lx\n", varName, v3Entry->existing_offset, variable_length(&v3Entry->header));
				break;
			}
		}

		v3Entry = nullptr;
	}

	if (v3Entry != nullptr) {
		if (existing) {
			*existing = v3Entry;
		}

		if (existingIndex) {
			*existingIndex = index;
		}
	}
}

IOReturn
IONVRAMV3Handler::unserializeImage(const uint8_t *image, IOByteCount length)
{
	OSSharedPtr<const OSSymbol>  propSymbol;
	OSSharedPtr<OSObject>        propObject;
	OSSharedPtr<OSData>          entryContainer;
	const struct v3_store_header *storeHeader;
	IOReturn                     ret = kIOReturnSuccess;
	size_t                       existingSize;
	struct nvram_v3_var_entry    *v3Entry;
	const struct v3_var_header   *header;
	size_t                       offset = sizeof(struct v3_store_header);
	uint32_t                     crc;
	unsigned int                 i;
	bool                         system;
	OSDictionary                 *dict;
	uuid_string_t                uuidString;

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
		IOFreeData(_nvramImage, _bankSize);
	}

	_varEntries.reset();
	_varEntries = OSArray::withCapacity(40);

	_nvramImage = IONewData(uint8_t, length);
	_bankSize = (uint32_t)length;
	bcopy(image, _nvramImage, _bankSize);

	if (_systemSize) {
		_systemDict = OSDictionary::withCapacity(1);
	}

	if (_commonSize) {
		_commonDict = OSDictionary::withCapacity(1);
	}

	while ((offset + sizeof(struct v3_var_header)) < length) {
		struct nvram_v3_var_entry *existingEntry = nullptr;
		unsigned int              existingIndex = 0;

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

		uuid_unparse(header->guid, uuidString);
		DEBUG_INFO("Valid var @ %#08zx, state=%#02x, length=%#08zx, %s:%s\n", offset, header->state,
		    variable_length(header), uuidString, header->name_data_buf);

		if (header->state != VAR_ADDED) {
			goto skip;
		}

		crc = crc32(0, header->name_data_buf + header->nameSize, header->dataSize);

		if (crc != header->crc) {
			DEBUG_ERROR("invalid crc @ %#lx, calculated=%#x, read=%#x\n", offset, crc, header->crc);
			goto skip;
		}

		v3Entry = (struct nvram_v3_var_entry *)IOMallocZeroData(nvram_v3_var_container_size(header));
		__nochk_memcpy(&v3Entry->header, _nvramImage + offset, variable_length(header));

		// It is assumed that the initial image being unserialized here is going to be the proxy data from EDT and not the image
		// read from the controller, which for various reasons due to the setting of states and saves from iBoot, can be
		// different. We will have an initial existing_offset of 0 and once the controller is set we will read
		// out the image there and update the existing offset with what is present on the NOR image
		v3Entry->existing_offset = 0;
		v3Entry->new_state = VAR_NEW_STATE_NONE;

		// safe guard for any strange duplicate entries in the store
		findExistingEntry(&v3Entry->header.guid, (const char *)v3Entry->header.name_data_buf, &existingEntry, &existingIndex);

		if (existingEntry != nullptr) {
			existingSize = variable_length(&existingEntry->header);

			entryContainer = OSData::withBytes(v3Entry, (uint32_t)nvram_v3_var_container_size(header));
			_varEntries->replaceObject(existingIndex, entryContainer.get());

			DEBUG_INFO("Found existing for %s, resetting when controller available\n", v3Entry->header.name_data_buf);
			_resetData = true;
		} else {
			entryContainer = OSData::withBytes(v3Entry, (uint32_t)nvram_v3_var_container_size(header));
			_varEntries->setObject(entryContainer.get());
			existingSize = 0;
		}

		system = (_systemSize != 0) && (uuid_compare(v3Entry->header.guid, gAppleSystemVariableGuid) == 0);
		if (system) {
			dict = _systemDict.get();
			_systemUsed = _systemUsed + (uint32_t)variable_length(header) - (uint32_t)existingSize;
		} else {
			dict = _commonDict.get();
			_commonUsed = _commonUsed + (uint32_t)variable_length(header) - (uint32_t)existingSize;
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
		IOFreeData(v3Entry, nvram_v3_var_container_size(header));
skip:
		offset += variable_length(header);
	}

	_currentOffset = (uint32_t)offset;

	DEBUG_ALWAYS("_commonSize %#x, _systemSize %#x, _currentOffset %#x\n", _commonSize, _systemSize, _currentOffset);
	DEBUG_INFO("_commonUsed %#x, _systemUsed %#x\n", _commonUsed, _systemUsed);

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
IONVRAMV3Handler::setVariable(const uuid_t varGuid, const char *variableName, OSObject *object)
{
	struct nvram_v3_var_entry *v3Entry = nullptr;
	struct nvram_v3_var_entry *newV3Entry;
	OSSharedPtr<OSData>       newContainer;
	bool                      unset = (object == nullptr);
	bool                      system = false;
	IOReturn                  ret = kIOReturnSuccess;
	size_t                    entryNameLen = strlen(variableName) + 1;
	unsigned int              existingEntryIndex;
	uint32_t                  dataSize = 0;
	size_t                    existingVariableSize = 0;
	size_t                    newVariableSize = 0;
	size_t                    newEntrySize;
	uuid_t                    destGuid;
	uuid_string_t             uuidString;

	if (_systemSize != 0) {
		// System region case, if they're using the GUID directly or it's on the system allow list
		// force it to use the System GUID
		if ((uuid_compare(varGuid, gAppleSystemVariableGuid) == 0) || variableInAllowList(variableName)) {
			system = true;
			uuid_copy(destGuid, gAppleSystemVariableGuid);
		} else {
			uuid_copy(destGuid, varGuid);
		}
	} else {
		// No system region, store System GUID as Common GUID
		if ((uuid_compare(varGuid, gAppleSystemVariableGuid) == 0) || variableInAllowList(variableName)) {
			uuid_copy(destGuid, gAppleNVRAMGuid);
		} else {
			uuid_copy(destGuid, varGuid);
		}
	}

	uuid_unparse(varGuid, uuidString);
	DEBUG_INFO("setting %s:%s, system=%d, current var count=%u\n", uuidString, variableName, system, _varEntries->getCount());

	uuid_unparse(destGuid, uuidString);
	DEBUG_INFO("using %s, _commonUsed %#x, _systemUsed %#x\n", uuidString, _commonUsed, _systemUsed);

	findExistingEntry(&destGuid, variableName, &v3Entry, &existingEntryIndex);

	if (unset == true) {
		setEntryForRemove(v3Entry, system);
	} else {
		if ((v3Entry != nullptr) && (v3Entry->new_state != VAR_NEW_STATE_REMOVE)) {
			// Sizing was subtracted in setEntryForRemove
			existingVariableSize = variable_length(&v3Entry->header);
		}

		convertObjectToProp(nullptr, &dataSize, variableName, object);

		newVariableSize = sizeof(struct v3_var_header) + entryNameLen + dataSize;
		newEntrySize = sizeof(struct nvram_v3_var_entry) + entryNameLen + dataSize;

		if (system) {
			if (_systemUsed - existingVariableSize + newVariableSize > _systemSize) {
				DEBUG_ERROR("system region full\n");
				ret = kIOReturnNoSpace;
				goto exit;
			}
		} else if (_commonUsed - existingVariableSize + newVariableSize > _commonSize) {
			DEBUG_ERROR("common region full\n");
			ret = kIOReturnNoSpace;
			goto exit;
		}

		DEBUG_INFO("creating new entry for %s, existingVariableSize=%#zx, newVariableSize=%#zx\n", variableName, existingVariableSize, newVariableSize);
		newV3Entry = (struct nvram_v3_var_entry *)IOMallocZeroData(newEntrySize);

		memcpy(newV3Entry->header.name_data_buf, variableName, entryNameLen);
		convertObjectToProp(newV3Entry->header.name_data_buf + entryNameLen, &dataSize, variableName, object);

		newV3Entry->header.startId = VARIABLE_DATA;
		newV3Entry->header.nameSize = (uint32_t)entryNameLen;
		newV3Entry->header.dataSize = dataSize;
		newV3Entry->header.crc = crc32(0, newV3Entry->header.name_data_buf + entryNameLen, dataSize);
		memcpy(newV3Entry->header.guid, &destGuid, sizeof(gAppleNVRAMGuid));
		newV3Entry->new_state = VAR_NEW_STATE_APPEND;

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
			_systemUsed = _systemUsed + (uint32_t)newVariableSize - (uint32_t)existingVariableSize;
			_provider->_systemDict->setObject(variableName, object);
		} else {
			_commonUsed = _commonUsed + (uint32_t)newVariableSize - (uint32_t)existingVariableSize;
			_provider->_commonDict->setObject(variableName, object);
		}

		if (_provider->_diags) {
			_provider->_diags->logVariable(getPartitionTypeForGUID(destGuid), kIONVRAMOperationWrite, variableName, (void *)(uintptr_t)dataSize);
		}

		IOFreeData(newV3Entry, newEntrySize);
	}

exit:
	_newData = true;

	if (_provider->_diags) {
		OSSharedPtr<OSNumber> val = OSNumber::withNumber(getSystemUsed(), 32);
		_provider->_diags->setProperty(kNVRAMSystemUsedKey, val.get());

		val = OSNumber::withNumber(getCommonUsed(), 32);
		_provider->_diags->setProperty(kNVRAMCommonUsedKey, val.get());
	}

	DEBUG_INFO("_commonUsed %#x, _systemUsed %#x\n", _commonUsed, _systemUsed);

	return ret;
}

uint32_t
IONVRAMV3Handler::findCurrentBank(void)
{
	struct v3_store_header storeHeader;
	uint32_t               maxGen = 0;
	uint32_t               currentBank = 0;

	for (unsigned int i = 0; i < _bankCount; i++) {
		_nvramController->select(i);
		_nvramController->read(0, (uint8_t *)&storeHeader, sizeof(storeHeader));

		if (valid_store_header(&storeHeader) && (storeHeader.generation >= maxGen)) {
			currentBank = i;
			maxGen = storeHeader.generation;
		}
	}

	DEBUG_ALWAYS("currentBank=%#x, gen=%#x", currentBank, maxGen);

	return currentBank;
}

bool
IONVRAMV3Handler::setController(IONVRAMController *controller)
{
	IOReturn ret = kIOReturnSuccess;

	if (_nvramController == NULL) {
		_nvramController = controller;
	}

	DEBUG_INFO("Controller name: %s\n", _nvramController->getName());

	require(_bankSize != 0, exit);

	if (_resetData) {
		_resetData = false;
		DEBUG_ERROR("_resetData set, issuing reclaim recovery\n");
		ret = reclaim();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reclaim recovery failed, invalid controller state!!! ret=%#x\n", ret));
		goto exit;
	}

	ret = reloadInternal();
	if (ret != kIOReturnSuccess) {
		DEBUG_ERROR("Invalid image found, issuing reclaim recovery\n");
		ret = reclaim();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reclaim recovery failed, invalid controller state!!! ret=%#x\n", ret));
	}

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
	uint32_t next_bank = (_currentBank + 1) % _bankCount;

	DEBUG_INFO("called\n");

	ret = _nvramController->select(next_bank);
	verify_noerr_action(ret, DEBUG_INFO("select of bank %#08x failed\n", next_bank));

	ret = _nvramController->eraseBank();
	verify_noerr_action(ret, DEBUG_INFO("eraseBank failed, ret=%#08x\n", ret));

	_currentBank = next_bank;

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
IONVRAMV3Handler::syncRaw(void)
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
	require_action(_bankSize != 0, exit, DEBUG_INFO("No nvram size info\n"));

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
			if ((_currentOffset + space_needed) > _bankSize) {
				ret = reclaim();
				require_noerr_action(ret, exit, DEBUG_ERROR("reclaim fail, ret=%#x\n", ret));

				// Check after reclaim...
				if ((_currentOffset + space_needed) > _bankSize) {
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

IOReturn
IONVRAMV3Handler::syncBlock(void)
{
	IOReturn             ret = kIOReturnSuccess;
	struct               v3_store_header newStoreHeader;
	struct               v3_var_header *varHeader;
	struct               nvram_v3_var_entry *varEntry;
	OSData               *entryContainer;
	size_t               new_bank_offset = sizeof(struct v3_store_header);
	uint8_t              *block;
	OSSharedPtr<OSArray> remainingEntries;
	uint32_t             next_bank = (_currentBank + 1) % _bankCount;

	DEBUG_INFO("called\n");

	require_action(_nvramController != nullptr, exit, DEBUG_INFO("No _nvramController\n"));
	require_action(_newData == true, exit, DEBUG_INFO("No _newData to sync\n"));
	require_action(_bankSize != 0, exit, DEBUG_INFO("No nvram size info\n"));

	block = (uint8_t *)IOMallocData(_bankSize);

	remainingEntries = OSArray::withCapacity(_varEntries->getCapacity());

	ret = _nvramController->select(next_bank);
	verify_noerr_action(ret, DEBUG_INFO("select of bank %#x failed\n", next_bank));

	ret = _nvramController->eraseBank();
	verify_noerr_action(ret, DEBUG_INFO("eraseBank failed, ret=%#08x\n", ret));

	_currentBank = next_bank;

	memcpy(&newStoreHeader, _nvramImage, sizeof(newStoreHeader));

	_generation += 1;

	newStoreHeader.generation = _generation;

	memcpy(block, (uint8_t *)&newStoreHeader, sizeof(newStoreHeader));

	for (unsigned int i = 0; i < _varEntries->getCount(); i++) {
		entryContainer = OSDynamicCast(OSData, _varEntries->getObject(i));
		varEntry = (struct nvram_v3_var_entry *)entryContainer->getBytesNoCopy();
		varHeader = &varEntry->header;

		varHeader->state = VAR_ADDED;

		DEBUG_INFO("entry %u %s, new_state=%#x, e_offset=%#lx, state=%#x\n",
		    i, varEntry->header.name_data_buf, varEntry->new_state, varEntry->existing_offset, varHeader->state);

		if (varEntry->new_state != VAR_NEW_STATE_REMOVE) {
			memcpy(block + new_bank_offset, (uint8_t *)varHeader, variable_length(varHeader));

			varEntry->existing_offset = new_bank_offset;
			new_bank_offset += variable_length(varHeader);
			varEntry->new_state = VAR_NEW_STATE_NONE;

			remainingEntries->setObject(entryContainer);
		} else {
			DEBUG_INFO("Dropping %s\n", varEntry->header.name_data_buf);
		}
	}

	ret = _nvramController->write(0, block, _bankSize);
	verify_noerr_action(ret, DEBUG_ERROR("w fail, ret=%#x\n", ret));

	_nvramController->sync();

	_varEntries.reset(remainingEntries.get(), OSRetain);

	_newData = false;

	DEBUG_INFO("Save complete, _generation=%u\n", _generation);

	IOFreeData(block, _bankSize);

exit:
	return ret;
}

bool
IONVRAMV3Handler::sync(void)
{
	IOReturn ret;

	if (_reload) {
		ret = reloadInternal();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reload failed, ret=%#x", ret));

		_reload = false;
	}

	if (_rawController == true) {
		ret = syncRaw();

		if (ret != kIOReturnSuccess) {
			ret = reclaim();
			require_noerr_action(ret, exit, DEBUG_ERROR("Reclaim recovery failed, ret=%#x", ret));

			// Attempt to save again (will rewrite the variables still in APPEND) on the new bank
			ret = syncRaw();
			require_noerr_action(ret, exit, DEBUG_ERROR("syncRaw retry failed, ret=%#x", ret));
		}
	} else {
		ret = syncBlock();
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
