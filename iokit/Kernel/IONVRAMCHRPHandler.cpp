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

#include <libkern/c++/OSBoundedPtr.h>

#define NVRAM_CHRP_APPLE_HEADER_NAME_V1  "nvram"
#define NVRAM_CHRP_APPLE_HEADER_NAME_V2  "2nvram"

#define NVRAM_CHRP_PARTITION_NAME_COMMON_V1   "common"
#define NVRAM_CHRP_PARTITION_NAME_SYSTEM_V1   "system"
#define NVRAM_CHRP_PARTITION_NAME_COMMON_V2   "2common"
#define NVRAM_CHRP_PARTITION_NAME_SYSTEM_V2   "2system"

#define NVRAM_CHRP_LENGTH_BLOCK_SIZE 0x10 // CHRP length field is in 16 byte blocks

typedef struct chrp_nvram_header { //16 bytes
	uint8_t  sig;
	uint8_t  cksum; // checksum on sig, len, and name
	uint16_t len;   // total length of the partition in 16 byte blocks starting with the signature
	// and ending with the last byte of data area, ie len includes its own header size
	char     name[12];
	uint8_t  data[0];
} chrp_nvram_header_t;

typedef struct apple_nvram_header {  // 16 + 16 bytes
	struct   chrp_nvram_header chrp;
	uint32_t adler;
	uint32_t generation;
	uint8_t  padding[8];
} apple_nvram_header_t;

typedef struct {
	NVRAMPartitionType type;
	uint32_t           offset;
	uint32_t           size;
} NVRAMRegionInfo;

class IONVRAMCHRPHandler : public IODTNVRAMFormatHandler, IOTypedOperatorsMixin<IONVRAMCHRPHandler>
{
private:
	bool              _newData;
	bool              _reload;
	IONVRAMController *_nvramController;
	IODTNVRAM         *_provider;
	NVRAMVersion      _version;
	uint32_t          _generation;

	uint8_t           *_nvramImage;

	uint32_t          _commonPartitionOffset;
	uint32_t          _commonPartitionSize;

	uint32_t          _systemPartitionOffset;
	uint32_t          _systemPartitionSize;

	OSSharedPtr<OSDictionary> &_varDict;

	uint32_t          _commonUsed;
	uint32_t          _systemUsed;

	uint32_t findCurrentBank(uint32_t *gen);
	IOReturn unserializeImage(const uint8_t *image, IOByteCount length);
	IOReturn serializeVariables(void);

	IOReturn reloadInternal(void);
	IOReturn setVariableInternal(const uuid_t varGuid, const char *variableName, OSObject *object);

	static OSSharedPtr<OSData> unescapeBytesToData(const uint8_t *bytes, uint32_t length);
	static OSSharedPtr<OSData> escapeDataToData(OSData * value);

	static bool convertPropToObject(const uint8_t *propName, uint32_t propNameLength, const uint8_t *propData, uint32_t propDataLength,
	    LIBKERN_RETURNS_RETAINED const OSSymbol **propSymbol, LIBKERN_RETURNS_RETAINED OSObject **propObject);
	static bool convertPropToObject(const uint8_t *propName, uint32_t propNameLength, const uint8_t *propData, uint32_t propDataLength,
	    OSSharedPtr<const OSSymbol>& propSymbol, OSSharedPtr<OSObject>& propObject);
	static bool convertObjectToProp(uint8_t *buffer, uint32_t *length, const OSSymbol *propSymbol, OSObject *propObject);
	static bool convertObjectToProp(uint8_t *buffer, uint32_t *length, const char *propSymbol, OSObject *propObject);

public:
	virtual
	~IONVRAMCHRPHandler() APPLE_KEXT_OVERRIDE;
	IONVRAMCHRPHandler(OSSharedPtr<OSDictionary> &varDict);

	static bool isValidImage(const uint8_t *image, IOByteCount length);

	static  IONVRAMCHRPHandler *init(IODTNVRAM *provider, const uint8_t *image, IOByteCount length,
	    OSSharedPtr<OSDictionary> &varDict);

	virtual IOReturn unserializeVariables(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn setVariable(const uuid_t varGuid, const char *variableName, OSObject *object) APPLE_KEXT_OVERRIDE;
	virtual bool     setController(IONVRAMController *controller) APPLE_KEXT_OVERRIDE;
	virtual bool     sync(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn flush(const uuid_t guid, IONVRAMOperation op) APPLE_KEXT_OVERRIDE;
	virtual void     reload(void) APPLE_KEXT_OVERRIDE;
	virtual uint32_t getGeneration(void) const APPLE_KEXT_OVERRIDE;
	virtual uint32_t getVersion(void) const APPLE_KEXT_OVERRIDE;
	virtual uint32_t getSystemUsed(void) const APPLE_KEXT_OVERRIDE;
	virtual uint32_t getCommonUsed(void) const APPLE_KEXT_OVERRIDE;
	virtual bool     getSystemPartitionActive(void) const APPLE_KEXT_OVERRIDE;
};

static const char *
get_bank_version_string(int version)
{
	switch (version) {
	case kNVRAMVersion1:
		return NVRAM_CHRP_APPLE_HEADER_NAME_V1;
	case kNVRAMVersion2:
		return NVRAM_CHRP_APPLE_HEADER_NAME_V2;
	default:
		return "Unknown";
	}
}

static uint32_t
adler32(const uint8_t *buffer, size_t length)
{
	uint32_t offset;
	uint32_t adler, lowHalf, highHalf;

	lowHalf = 1;
	highHalf = 0;

	for (offset = 0; offset < length; offset++) {
		if ((offset % 5000) == 0) {
			lowHalf  %= 65521L;
			highHalf %= 65521L;
		}

		lowHalf += buffer[offset];
		highHalf += lowHalf;
	}

	lowHalf  %= 65521L;
	highHalf %= 65521L;

	adler = (highHalf << 16) | lowHalf;

	return adler;
}

static uint32_t
nvram_get_adler(uint8_t *buf, int version)
{
	return ((struct apple_nvram_header *)buf)->adler;
}

static uint32_t
adler32_with_version(const uint8_t *buf, size_t len, int version)
{
	size_t offset;

	switch (version) {
	case kNVRAMVersion1:
	case kNVRAMVersion2:
		offset = offsetof(struct apple_nvram_header, generation);
		break;
	default:
		return 0;
	}

	return adler32(buf + offset, len - offset);
}

static uint8_t
chrp_checksum(const struct chrp_nvram_header *hdr)
{
	uint16_t      sum;
	const uint8_t *p;
	const uint8_t *begin = (const uint8_t *)hdr + offsetof(struct chrp_nvram_header, len);
	const uint8_t *end = (const uint8_t *)hdr + offsetof(struct chrp_nvram_header, data);

	// checksum the header (minus the checksum itself)
	sum = hdr->sig;
	for (p = begin; p < end; p++) {
		sum += *p;
	}
	while (sum > 0xff) {
		sum = (sum & 0xff) + (sum >> 8);
	}

	return sum & 0xff;
}

static IOReturn
nvram_validate_header_v1v2(const uint8_t * buf, uint32_t *generation, int version)
{
	IOReturn   result = kIOReturnError;
	uint8_t    checksum;
	const char *header_string = get_bank_version_string(version);
	struct     chrp_nvram_header *chrp_header = (struct chrp_nvram_header *)buf;
	uint32_t   local_gen = 0;

	require(buf != nullptr, exit);

	// <rdar://problem/73454488> Recovery Mode [Internal Build] 18D52-->18E141 [J307/308 Only]
	// we can only compare the first "nvram" parts of the name as some devices have additional junk from
	// a previous build likely copying past bounds of the "nvram" name in the const section
	if (memcmp(header_string, chrp_header->name, strlen(header_string)) == 0) {
		checksum = chrp_checksum(chrp_header);
		if (checksum == chrp_header->cksum) {
			result = kIOReturnSuccess;
			local_gen = ((struct apple_nvram_header*)buf)->generation;

			DEBUG_INFO("Found %s gen=%u\n", header_string, local_gen);

			if (generation) {
				*generation = local_gen;
			}
		} else {
			DEBUG_INFO("invalid checksum in header, found %#02x, expected %#02x\n", chrp_header->cksum, checksum);
		}
	} else {
		DEBUG_INFO("invalid bank for \"%s\", name = %#02x %#02x %#02x %#02x\n", header_string,
		    chrp_header->name[0],
		    chrp_header->name[1],
		    chrp_header->name[2],
		    chrp_header->name[3]);
	}

exit:
	return result;
}

static void
nvram_set_apple_header(uint8_t *buf, size_t len, uint32_t generation, int version)
{
	if (version == kNVRAMVersion1 ||
	    version == kNVRAMVersion2) {
		struct apple_nvram_header *apple_hdr = (struct apple_nvram_header *)buf;
		generation += 1;
		apple_hdr->generation = generation;
		apple_hdr->adler = adler32_with_version(buf, len, version);
	}
}

static NVRAMVersion
validateNVRAMVersion(const uint8_t *buf, size_t len, uint32_t *generation)
{
	NVRAMVersion version = kNVRAMVersionUnknown;

	if (nvram_validate_header_v1v2(buf, generation, kNVRAMVersion1) == kIOReturnSuccess) {
		version = kNVRAMVersion1;
		goto exit;
	}

	if (nvram_validate_header_v1v2(buf, generation, kNVRAMVersion2) == kIOReturnSuccess) {
		version = kNVRAMVersion2;
		goto exit;
	}

	DEBUG_INFO("Unable to determine version\n");

exit:
	DEBUG_INFO("version=%u\n", version);
	return version;
}

IONVRAMCHRPHandler::~IONVRAMCHRPHandler()
{
}

bool
IONVRAMCHRPHandler::isValidImage(const uint8_t *image, IOByteCount length)
{
	return validateNVRAMVersion(image, length, nullptr) != kNVRAMVersionUnknown;
}

IONVRAMCHRPHandler*
IONVRAMCHRPHandler::init(IODTNVRAM *provider, const uint8_t *image, IOByteCount length,
    OSSharedPtr<OSDictionary> &varDict)
{
	bool propertiesOk;

	IONVRAMCHRPHandler *handler = new IONVRAMCHRPHandler(varDict);

	handler->_provider = provider;

	propertiesOk = handler->getNVRAMProperties();
	require_action(propertiesOk, exit, DEBUG_ERROR("Unable to get NVRAM properties\n"));

	require_action(length == handler->_bankSize, exit, DEBUG_ERROR("length 0x%llx != _bankSize 0x%x\n", length, handler->_bankSize));

	if ((image != nullptr) && (length != 0)) {
		if (handler->unserializeImage(image, length) != kIOReturnSuccess) {
			DEBUG_ALWAYS("Unable to unserialize image, len=%#x\n", (unsigned int)length);
		}
	}

	return handler;

exit:
	delete handler;

	return nullptr;
}

IONVRAMCHRPHandler::IONVRAMCHRPHandler(OSSharedPtr<OSDictionary> &varDict) :
	_commonPartitionSize(0x800),
	_varDict(varDict)
{
}

IOReturn
IONVRAMCHRPHandler::flush(const uuid_t guid, IONVRAMOperation op)
{
	IOReturn ret = kIOReturnSuccess;
	bool     flushSystem;
	bool     flushCommon;

	flushSystem = getSystemPartitionActive() && (uuid_compare(guid, gAppleSystemVariableGuid) == 0);
	flushCommon = uuid_compare(guid, gAppleNVRAMGuid) == 0;

	DEBUG_INFO("flushSystem=%d, flushCommon=%d\n", flushSystem, flushCommon);

	if (flushSystem || flushCommon) {
		const OSSymbol                    *canonicalKey;
		OSSharedPtr<OSDictionary>         dictCopy;
		OSSharedPtr<OSCollectionIterator> iter;
		uuid_string_t                     uuidString;

		dictCopy = OSDictionary::withDictionary(_varDict.get());
		iter = OSCollectionIterator::withCollection(dictCopy.get());
		require_action(dictCopy && iter, exit, ret = kIOReturnNoMemory);

		while ((canonicalKey = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			const char *varName;
			uuid_t     varGuid;
			bool       clear;

			parseVariableName(canonicalKey->getCStringNoCopy(), &varGuid, &varName);

			uuid_unparse(varGuid, uuidString);

			clear = ((flushSystem && (uuid_compare(varGuid, gAppleSystemVariableGuid) == 0)) ||
			    (flushCommon && (uuid_compare(varGuid, gAppleSystemVariableGuid) != 0))) &&
			    verifyPermission(op, varGuid, varName, getSystemPartitionActive());

			if (clear) {
				DEBUG_INFO("Clearing entry for %s:%s\n", uuidString, varName);
				setVariableInternal(varGuid, varName, nullptr);
			} else {
				DEBUG_INFO("Keeping entry for %s:%s\n", uuidString, varName);
			}
		}
	}

exit:
	return ret;
}

IOReturn
IONVRAMCHRPHandler::reloadInternal(void)
{
	uint32_t controllerBank;
	uint32_t controllerGen;

	controllerBank = findCurrentBank(&controllerGen);

	if (_currentBank != controllerBank) {
		DEBUG_ERROR("_currentBank 0x%x != controllerBank 0x%x", _currentBank, controllerBank);
	}

	if (_generation != controllerGen) {
		DEBUG_ERROR("_generation 0x%x != controllerGen 0x%x", _generation, controllerGen);
	}

	_currentBank = controllerBank;
	_generation = controllerGen;

	return kIOReturnSuccess;
}

void
IONVRAMCHRPHandler::reload(void)
{
	_reload = true;

	DEBUG_INFO("reload marked\n");
}

IOReturn
IONVRAMCHRPHandler::unserializeImage(const uint8_t *image, IOByteCount length)
{
	IOReturn ret = kIOReturnInvalid;
	uint32_t partitionOffset, partitionLength;
	uint32_t currentLength, currentOffset = 0;
	uint32_t hdr_adler, calculated_adler;

	_commonPartitionOffset = 0xFFFFFFFF;
	_systemPartitionOffset = 0xFFFFFFFF;

	_version = validateNVRAMVersion(image, _bankSize, &_generation);
	require(_version != kNVRAMVersionUnknown, exit);

	if (_nvramImage) {
		IOFreeData(_nvramImage, _bankSize);
	}

	_nvramImage = IONewData(uint8_t, length);
	_bankSize = (uint32_t)length;
	bcopy(image, _nvramImage, _bankSize);

	hdr_adler = nvram_get_adler(_nvramImage, _version);
	calculated_adler = adler32_with_version(_nvramImage, _bankSize, _version);

	if (hdr_adler != calculated_adler) {
		panic("header adler %#08X != calculated_adler %#08X\n", hdr_adler, calculated_adler);
	}

	// Look through the partitions to find the common and system partitions.
	while (currentOffset < _bankSize) {
		bool common_partition;
		bool system_partition;
		const chrp_nvram_header_t * header = (chrp_nvram_header_t *)(_nvramImage + currentOffset);
		const uint8_t common_v1_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_COMMON_V1};
		const uint8_t common_v2_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_COMMON_V2};
		const uint8_t system_v1_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_SYSTEM_V1};
		const uint8_t system_v2_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_SYSTEM_V2};

		currentLength = header->len * NVRAM_CHRP_LENGTH_BLOCK_SIZE;

		if (currentLength < sizeof(chrp_nvram_header_t)) {
			break;
		}

		partitionOffset = currentOffset + sizeof(chrp_nvram_header_t);
		partitionLength = currentLength - sizeof(chrp_nvram_header_t);

		if ((partitionOffset + partitionLength) > _bankSize) {
			break;
		}

		common_partition = (memcmp(header->name, common_v1_name, sizeof(header->name)) == 0) ||
		    (memcmp(header->name, common_v2_name, sizeof(header->name)) == 0);
		system_partition = (memcmp(header->name, system_v1_name, sizeof(header->name)) == 0) ||
		    (memcmp(header->name, system_v2_name, sizeof(header->name)) == 0);

		if (common_partition) {
			_commonPartitionOffset = partitionOffset;
			_commonPartitionSize = partitionLength;
		} else if (system_partition) {
			_systemPartitionOffset = partitionOffset;
			_systemPartitionSize = partitionLength;
		}
		currentOffset += currentLength;
	}

	ret = kIOReturnSuccess;

exit:
	_varDict = OSDictionary::withCapacity(1);

	DEBUG_ALWAYS("NVRAM : commonPartitionOffset - %#x, commonPartitionSize - %#x, systemPartitionOffset - %#x, systemPartitionSize - %#x\n",
	    _commonPartitionOffset, _commonPartitionSize, _systemPartitionOffset, _systemPartitionSize);

	return ret;
}

IOReturn
IONVRAMCHRPHandler::unserializeVariables(void)
{
	uint32_t                    cnt, cntStart;
	const uint8_t               *propName, *propData;
	uint32_t                    propNameLength, propDataLength, regionIndex;
	OSSharedPtr<const OSSymbol> propSymbol;
	OSSharedPtr<OSObject>       propObject;
	NVRAMRegionInfo             *currentRegion;
	NVRAMRegionInfo             variableRegions[] = { { kIONVRAMPartitionCommon, _commonPartitionOffset, _commonPartitionSize},
							  { kIONVRAMPartitionSystem, _systemPartitionOffset, _systemPartitionSize} };

	DEBUG_INFO("...\n");

	for (regionIndex = 0; regionIndex < ARRAY_SIZE(variableRegions); regionIndex++) {
		currentRegion = &variableRegions[regionIndex];
		const uint8_t * imageData = _nvramImage + currentRegion->offset;

		if (currentRegion->size == 0) {
			continue;
		}

		DEBUG_INFO("region = %d\n", currentRegion->type);
		cnt = 0;
		while (cnt < currentRegion->size) {
			cntStart = cnt;
			// Break if there is no name.
			if (imageData[cnt] == '\0') {
				break;
			}

			// Find the length of the name.
			propName = imageData + cnt;
			for (propNameLength = 0; (cnt + propNameLength) < currentRegion->size;
			    propNameLength++) {
				if (imageData[cnt + propNameLength] == '=') {
					break;
				}
			}

			// Break if the name goes past the end of the partition.
			if ((cnt + propNameLength) >= currentRegion->size) {
				break;
			}
			cnt += propNameLength + 1;

			propData = imageData + cnt;
			for (propDataLength = 0; (cnt + propDataLength) < currentRegion->size;
			    propDataLength++) {
				if (imageData[cnt + propDataLength] == '\0') {
					break;
				}
			}

			// Break if the data goes past the end of the partition.
			if ((cnt + propDataLength) >= currentRegion->size) {
				break;
			}
			cnt += propDataLength + 1;

			if (convertPropToObject(propName, propNameLength, propData, propDataLength, propSymbol, propObject)) {
				OSSharedPtr<const OSSymbol> canonicalKey;
				const char                  *varName = propSymbol.get()->getCStringNoCopy();
				uint32_t                    variableLength = cnt - cntStart;

				DEBUG_INFO("adding %s, variableLength=%#x,dataLength=%#x\n", varName, variableLength, propDataLength);

				if (currentRegion->type == kIONVRAMPartitionCommon) {
					canonicalKey = keyWithGuidAndCString(gAppleNVRAMGuid, varName);
				} else if (currentRegion->type == kIONVRAMPartitionSystem) {
					canonicalKey = keyWithGuidAndCString(gAppleSystemVariableGuid, varName);
				}

				DEBUG_INFO("adding %s, dataLength=%u\n", varName, propDataLength);
				_varDict->setObject(canonicalKey.get(), propObject.get());
				if (_provider->_diags) {
					_provider->_diags->logVariable(currentRegion->type,
					    kIONVRAMOperationInit, varName,
					    (void *)(uintptr_t)(cnt - cntStart));
				}

				if (currentRegion->type == kIONVRAMPartitionSystem) {
					_systemUsed += variableLength;
				} else if (currentRegion->type == kIONVRAMPartitionCommon) {
					_commonUsed += variableLength;
				}
			}
		}
	}

	if (_provider->_diags) {
		OSSharedPtr<OSNumber> val = OSNumber::withNumber(getSystemUsed(), 32);
		_provider->_diags->setProperty(kNVRAMSystemUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMSystemUsedKey, getSystemUsed());

		val = OSNumber::withNumber(getCommonUsed(), 32);
		_provider->_diags->setProperty(kNVRAMCommonUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMCommonUsedKey, getCommonUsed());
	}

	// Create the boot-args property if it is not in the dictionary.
	if (_provider->getProperty(kIONVRAMBootArgsKey) == nullptr) {
		propSymbol = OSSymbol::withCString(kIONVRAMBootArgsKey);
		propObject = OSString::withCStringNoCopy("");

		_provider->setProperty(propSymbol.get(), propObject.get());
	}

	_newData = true;

	DEBUG_INFO("%s _varDict=%p\n", __FUNCTION__, _varDict ? _varDict.get() : nullptr);

	return kIOReturnSuccess;
}

IOReturn
IONVRAMCHRPHandler::serializeVariables(void)
{
	IOReturn                          ret;
	bool                              ok = false;
	uint32_t                          length, maxLength, regionIndex;
	uint8_t                           *buffer, *tmpBuffer;
	const OSSymbol                    *tmpSymbol;
	OSObject                          *tmpObject;
	OSSharedPtr<OSCollectionIterator> iter;
	OSSharedPtr<OSNumber>             generation;
	uint8_t                           *nvramImage;
	NVRAMRegionInfo                   *currentRegion;
	NVRAMRegionInfo                   variableRegions[] = { { kIONVRAMPartitionCommon, _commonPartitionOffset, _commonPartitionSize},
								{ kIONVRAMPartitionSystem, _systemPartitionOffset, _systemPartitionSize} };

	require_action(_nvramController != nullptr, exit, (ret = kIOReturnNotReady, DEBUG_ERROR("No _nvramController\n")));
	require_action(_newData == true, exit, (ret = kIOReturnSuccess, DEBUG_INFO("No _newData to sync\n")));
	require_action(_bankSize != 0, exit, (ret = kIOReturnSuccess, DEBUG_INFO("No nvram size info\n")));
	require_action(_nvramImage != nullptr, exit, (ret = kIOReturnSuccess, DEBUG_INFO("No nvram image info\n")));

	nvramImage = IONewZeroData(uint8_t, _bankSize);
	require_action(nvramImage != nullptr, exit, (ret = kIOReturnNoMemory, DEBUG_ERROR("Can't create NVRAM image copy\n")));

	DEBUG_INFO("...\n");

	bcopy(_nvramImage, nvramImage, _bankSize);

	for (regionIndex = 0; regionIndex < ARRAY_SIZE(variableRegions); regionIndex++) {
		currentRegion = &variableRegions[regionIndex];

		if (currentRegion->size == 0) {
			continue;
		}

		DEBUG_INFO("region = %d\n", currentRegion->type);
		buffer = tmpBuffer = nvramImage + currentRegion->offset;

		bzero(buffer, currentRegion->size);

		ok = true;
		maxLength = currentRegion->size;

		iter = OSCollectionIterator::withCollection(_varDict.get());
		if (iter == nullptr) {
			ok = false;
		}

		while (ok) {
			uuid_t entryGuid;
			const char *entryName;

			tmpSymbol = OSDynamicCast(OSSymbol, iter->getNextObject());

			if (tmpSymbol == nullptr) {
				break;
			}

			DEBUG_INFO("_varDict entry %s\n", tmpSymbol->getCStringNoCopy());

			parseVariableName(tmpSymbol, &entryGuid, &entryName);

			if (getSystemPartitionActive()) {
				if (currentRegion->type == kIONVRAMPartitionSystem) {
					if (uuid_compare(entryGuid, gAppleSystemVariableGuid) != 0) {
						DEBUG_INFO("Skipping %s because not system var\n", entryName);
						continue;
					}
				} else if (currentRegion->type == kIONVRAMPartitionCommon) {
					if (uuid_compare(entryGuid, gAppleSystemVariableGuid) == 0) {
						DEBUG_INFO("Skipping %s for common region\n", entryName);
						continue;
					}
				}
			}

			DEBUG_INFO("adding variable %s\n", entryName);

			tmpObject = _varDict->getObject(tmpSymbol);

			length = maxLength;
			ok = convertObjectToProp(tmpBuffer, &length, entryName, tmpObject);
			if (ok) {
				tmpBuffer += length;
				maxLength -= length;
			}
		}

		if (!ok) {
			ret = kIOReturnNoSpace;
			IODeleteData(nvramImage, uint8_t, _bankSize);
			break;
		}

		if (currentRegion->type == kIONVRAMPartitionSystem) {
			_systemUsed = (uint32_t)(tmpBuffer - buffer);
		} else if (currentRegion->type == kIONVRAMPartitionCommon) {
			_commonUsed = (uint32_t)(tmpBuffer - buffer);
		}
	}

	DEBUG_INFO("ok=%d\n", ok);
	require(ok, exit);

	nvram_set_apple_header(nvramImage, _bankSize, ++_generation, _version);

	_currentBank = (_currentBank + 1) % _bankCount;

	ret = _nvramController->select(_currentBank);
	DEBUG_IFERROR(ret, "_currentBank=%#x, select=%#x\n", _currentBank, ret);

	ret = _nvramController->eraseBank();
	DEBUG_IFERROR(ret, "eraseBank=%#x\n", ret);

	ret = _nvramController->write(0, nvramImage, _bankSize);
	DEBUG_IFERROR(ret, "write=%#x\n", ret);

	_nvramController->sync();

	if (_nvramImage) {
		IODeleteData(_nvramImage, uint8_t, _bankSize);
	}

	_nvramImage = nvramImage;

	_newData = false;

exit:
	return ret;
}

IOReturn
IONVRAMCHRPHandler::setVariableInternal(const uuid_t varGuid, const char *variableName, OSObject *object)
{
	uint32_t                    newSize = 0;
	uint32_t                    existingSize = 0;
	bool                        remove = (object == nullptr);
	OSObject                    *existing;
	OSSharedPtr<const OSSymbol> canonicalKey;
	bool                        systemVar;

	systemVar = (uuid_compare(varGuid, gAppleSystemVariableGuid) == 0);
	canonicalKey = keyWithGuidAndCString(varGuid, variableName);

	if ((existing = _varDict->getObject(canonicalKey.get()))) {
		convertObjectToProp(nullptr, &existingSize, variableName, existing);
	}

	if (remove == false) {
		convertObjectToProp(nullptr, &newSize, variableName, object);

		DEBUG_INFO("setting %s, systemVar=%d, existingSize=%u, newSize=%u\n", canonicalKey.get()->getCStringNoCopy(), systemVar, existingSize, newSize);

		if (systemVar) {
			if ((newSize + _systemUsed - existingSize) > _systemPartitionSize) {
				DEBUG_ERROR("No space left in system partition, need=%#x, _systemUsed=%#x, _systemPartitionSize=%#x\n",
				    newSize, _systemUsed, _systemPartitionSize);
				return kIOReturnNoSpace;
			} else {
				_systemUsed = _systemUsed + newSize - existingSize;
			}
		} else {
			if ((newSize + _commonUsed - existingSize) > _commonPartitionSize) {
				DEBUG_ERROR("No space left in common partition, need=%#x, _commonUsed=%#x, _commonPartitionSize=%#x\n",
				    newSize, _commonUsed, _commonPartitionSize);
				return kIOReturnNoSpace;
			} else {
				_commonUsed = _commonUsed + newSize - existingSize;
			}
		}

		_varDict->setObject(canonicalKey.get(), object);

		if (_provider->_diags) {
			_provider->_diags->logVariable(getPartitionTypeForGUID(varGuid),
			    kIONVRAMOperationWrite, variableName,
			    (void *)(uintptr_t)newSize);
		}
	} else {
		DEBUG_INFO("removing %s, systemVar=%d, existingSize=%u\n", canonicalKey.get()->getCStringNoCopy(), systemVar, existingSize);

		if (systemVar) {
			_systemUsed -= existingSize;
		} else {
			_commonUsed -= existingSize;
		}

		_varDict->removeObject(canonicalKey.get());

		if (_provider->_diags) {
			_provider->_diags->logVariable(getPartitionTypeForGUID(varGuid),
			    kIONVRAMOperationDelete, variableName,
			    nullptr);
		}
	}

	if (_provider->_diags) {
		OSSharedPtr<OSNumber> val = OSNumber::withNumber(getSystemUsed(), 32);
		_provider->_diags->setProperty(kNVRAMSystemUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMSystemUsedKey, getSystemUsed());

		val = OSNumber::withNumber(getCommonUsed(), 32);
		_provider->_diags->setProperty(kNVRAMCommonUsedKey, val.get());
		DEBUG_INFO("%s=%u\n", kNVRAMCommonUsedKey, getCommonUsed());
	}

	_newData = true;

	return kIOReturnSuccess;
}

IOReturn
IONVRAMCHRPHandler::setVariable(const uuid_t varGuid, const char *variableName, OSObject *object)
{
	uuid_t destGuid;

	if (getSystemPartitionActive()) {
		// System region case, if they're using the GUID directly or it's on the system allow list
		// force it to use the System GUID
		if ((uuid_compare(varGuid, gAppleSystemVariableGuid) == 0) || variableInAllowList(variableName)) {
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

	return setVariableInternal(destGuid, variableName, object);
}

uint32_t
IONVRAMCHRPHandler::findCurrentBank(uint32_t *gen)
{
	struct apple_nvram_header storeHeader;
	uint32_t                  maxGen = 0;
	uint32_t                  currentBank = 0;

	for (unsigned int i = 0; i < _bankCount; i++) {
		NVRAMVersion bankVer;
		uint32_t bankGen = 0;

		_nvramController->select(i);
		_nvramController->read(0, (uint8_t *)&storeHeader, sizeof(storeHeader));
		bankVer = validateNVRAMVersion((uint8_t *)&storeHeader, sizeof(storeHeader), &bankGen);

		if ((bankVer != kNVRAMVersionUnknown) && (bankGen >= maxGen)) {
			currentBank = i;
			maxGen = bankGen;
		}
	}

	DEBUG_ALWAYS("currentBank=%#x, gen=%#x", currentBank, maxGen);

	*gen = maxGen;
	return currentBank;
}

bool
IONVRAMCHRPHandler::setController(IONVRAMController *controller)
{
	IOReturn ret;

	if (_nvramController == NULL) {
		_nvramController = controller;
	}

	DEBUG_INFO("Controller name: %s\n", _nvramController->getName());

	ret = reloadInternal();
	if (ret != kIOReturnSuccess) {
		DEBUG_ERROR("reloadInternal failed, ret=0x%08x\n", ret);
	}

	return true;
}

bool
IONVRAMCHRPHandler::sync(void)
{
	IOReturn ret;

	if (_reload) {
		ret = reloadInternal();
		require_noerr_action(ret, exit, DEBUG_ERROR("Reload failed, ret=%#x", ret));

		_reload = false;
	}

	ret = serializeVariables();
	require_noerr_action(ret, exit, DEBUG_ERROR("serializeVariables failed, ret=%#x", ret));

exit:
	return ret;
}

uint32_t
IONVRAMCHRPHandler::getGeneration(void) const
{
	return _generation;
}

uint32_t
IONVRAMCHRPHandler::getVersion(void) const
{
	return _version;
}

uint32_t
IONVRAMCHRPHandler::getSystemUsed(void) const
{
	return _systemUsed;
}

uint32_t
IONVRAMCHRPHandler::getCommonUsed(void) const
{
	return _commonUsed;
}

bool
IONVRAMCHRPHandler::getSystemPartitionActive(void) const
{
	return _systemPartitionSize != 0;
}

OSSharedPtr<OSData>
IONVRAMCHRPHandler::unescapeBytesToData(const uint8_t *bytes, uint32_t length)
{
	OSSharedPtr<OSData> data;
	uint32_t            totalLength = 0;
	uint32_t            offset, offset2;
	uint8_t             byte;
	bool                ok;

	// Calculate the actual length of the data.
	ok = true;
	totalLength = 0;
	for (offset = 0; offset < length;) {
		byte = bytes[offset++];
		if (byte == 0xFF) {
			byte = bytes[offset++];
			if (byte == 0x00) {
				ok = false;
				break;
			}
			offset2 = byte & 0x7F;
		} else {
			offset2 = 1;
		}
		totalLength += offset2;
	}

	if (ok) {
		// Create an empty OSData of the correct size.
		data = OSData::withCapacity(totalLength);
		if (data != nullptr) {
			for (offset = 0; offset < length;) {
				byte = bytes[offset++];
				if (byte == 0xFF) {
					byte = bytes[offset++];
					offset2 = byte & 0x7F;
					byte = (byte & 0x80) ? 0xFF : 0x00;
				} else {
					offset2 = 1;
				}
				data->appendByte(byte, offset2);
			}
		}
	}

	return data;
}

OSSharedPtr<OSData>
IONVRAMCHRPHandler::escapeDataToData(OSData * value)
{
	OSSharedPtr<OSData>         result;
	OSBoundedPtr<const uint8_t> startPtr;
	const uint8_t               *endPtr;
	const uint8_t               *valueBytesPtr;
	OSBoundedPtr<const uint8_t> wherePtr;
	uint8_t                     byte;
	bool                        ok = true;

	valueBytesPtr = (const uint8_t *) value->getBytesNoCopy();
	endPtr = valueBytesPtr + value->getLength();
	wherePtr = OSBoundedPtr<const uint8_t>(valueBytesPtr, valueBytesPtr, endPtr);

	result = OSData::withCapacity((unsigned int)(endPtr - wherePtr));
	if (!result) {
		return result;
	}

	while (wherePtr < endPtr) {
		startPtr = wherePtr;
		byte = *wherePtr++;
		if ((byte == 0x00) || (byte == 0xFF)) {
			for (;
			    ((wherePtr - startPtr) < 0x7F) && (wherePtr < endPtr) && (byte == *wherePtr);
			    wherePtr++) {
			}
			ok &= result->appendByte(0xff, 1);
			byte = (byte & 0x80) | ((uint8_t)(wherePtr - startPtr));
		}
		ok &= result->appendByte(byte, 1);
	}
	ok &= result->appendByte(0, 1);

	if (!ok) {
		result.reset();
	}

	return result;
}

bool
IONVRAMCHRPHandler::convertPropToObject(const uint8_t *propName, uint32_t propNameLength,
    const uint8_t *propData, uint32_t propDataLength,
    const OSSymbol **propSymbol,
    OSObject **propObject)
{
	OSSharedPtr<const OSString> delimitedName;
	OSSharedPtr<const OSSymbol> tmpSymbol;
	OSSharedPtr<OSNumber>       tmpNumber;
	OSSharedPtr<OSString>       tmpString;
	OSSharedPtr<OSObject>       tmpObject = nullptr;

	delimitedName = OSString::withCString((const char *)propName, propNameLength);
	tmpSymbol = OSSymbol::withString(delimitedName.get());

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
		tmpObject = unescapeBytesToData(propData, propDataLength);
		break;

	default:
		break;
	}

	if (tmpObject == nullptr) {
		tmpSymbol.reset();
		return false;
	}

	*propSymbol = tmpSymbol.detach();
	*propObject = tmpObject.detach();

	return true;
}

bool
IONVRAMCHRPHandler::convertPropToObject(const uint8_t *propName, uint32_t propNameLength,
    const uint8_t *propData, uint32_t propDataLength,
    OSSharedPtr<const OSSymbol>& propSymbol,
    OSSharedPtr<OSObject>& propObject)
{
	const OSSymbol* propSymbolRaw = nullptr;
	OSObject* propObjectRaw       = nullptr;

	bool ok = convertPropToObject(propName, propNameLength, propData, propDataLength,
	    &propSymbolRaw, &propObjectRaw);

	propSymbol.reset(propSymbolRaw, OSNoRetain);
	propObject.reset(propObjectRaw, OSNoRetain);

	return ok;
}

bool
IONVRAMCHRPHandler::convertObjectToProp(uint8_t *buffer, uint32_t *length,
    const OSSymbol *propSymbol, OSObject *propObject)
{
	return convertObjectToProp(buffer, length, propSymbol->getCStringNoCopy(), propObject);
}

bool
IONVRAMCHRPHandler::convertObjectToProp(uint8_t *buffer, uint32_t *length,
    const char *propName, OSObject *propObject)
{
	uint32_t             propNameLength, propDataLength, remaining, offset;
	IONVRAMVariableType  propType;
	OSBoolean            *tmpBoolean = nullptr;
	OSNumber             *tmpNumber = nullptr;
	OSString             *tmpString = nullptr;
	OSSharedPtr<OSData>  tmpData;

	propNameLength = (uint32_t)strlen(propName);
	propType = getVariableType(propName);
	offset = 0;
	remaining = 0;

	// Get the size of the data.
	propDataLength = 0xFFFFFFFF;
	switch (propType) {
	case kOFVariableTypeBoolean:
		tmpBoolean = OSDynamicCast(OSBoolean, propObject);
		if (tmpBoolean != nullptr) {
			propDataLength = 5;
		}
		break;

	case kOFVariableTypeNumber:
		tmpNumber = OSDynamicCast(OSNumber, propObject);
		if (tmpNumber != nullptr) {
			propDataLength = 10;
		}
		break;

	case kOFVariableTypeString:
		tmpString = OSDynamicCast(OSString, propObject);
		if (tmpString != nullptr) {
			propDataLength = tmpString->getLength();
		}
		break;

	case kOFVariableTypeData:
		tmpData.reset(OSDynamicCast(OSData, propObject), OSNoRetain);
		if (tmpData != nullptr) {
			tmpData = escapeDataToData(tmpData.detach());
			// escapeDataToData() adds the NULL byte to the data
			// subtract 1 here to keep offset consistent with the other cases
			propDataLength = tmpData->getLength() - 1;
		}
		break;

	default:
		break;
	}

	// Make sure the propertySize is known and will fit.
	if (propDataLength == 0xFFFFFFFF) {
		return false;
	}

	if (buffer) {
		// name + '=' + data + '\0'
		if ((propNameLength + propDataLength + 2) > *length) {
			return false;
		}

		remaining = *length;
	}

	*length = 0;

	// Copy the property name equal sign.
	offset += snprintf((char *)buffer, remaining, "%s=", propName);
	if (buffer) {
		if (remaining > offset) {
			buffer += offset;
			remaining = remaining - offset;
		} else {
			return false;
		}
	}

	switch (propType) {
	case kOFVariableTypeBoolean:
		if (tmpBoolean->getValue()) {
			offset += strlcpy((char *)buffer, "true", remaining);
		} else {
			offset += strlcpy((char *)buffer, "false", remaining);
		}
		break;

	case kOFVariableTypeNumber:
	{
		uint32_t tmpValue = tmpNumber->unsigned32BitValue();
		if (tmpValue == 0xFFFFFFFF) {
			offset += strlcpy((char *)buffer, "-1", remaining);
		} else if (tmpValue < 1000) {
			offset += snprintf((char *)buffer, remaining, "%d", (uint32_t)tmpValue);
		} else {
			offset += snprintf((char *)buffer, remaining, "%#x", (uint32_t)tmpValue);
		}
	}
	break;

	case kOFVariableTypeString:
		offset += strlcpy((char *)buffer, tmpString->getCStringNoCopy(), remaining);
		break;

	case kOFVariableTypeData:
		if (buffer) {
			bcopy(tmpData->getBytesNoCopy(), buffer, propDataLength);
		}
		tmpData.reset();
		offset += propDataLength;
		break;

	default:
		break;
	}

	*length = offset + 1;

	return true;
}
