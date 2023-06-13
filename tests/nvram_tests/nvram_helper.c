#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <darwintest.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "nvram_helper.h"

//  Ascii value of 'A' (65) - Ascii value of '9' (57)
#define ASCII_OFFSET 7
#define NVRAM_BYTE_LEN 3

// NVRAM helper functions from https://stashweb.sd.apple.com/projects/COREOS/repos/system_cmds/browse/nvram.tproj/nvram.c

/**
 * @brief Print the given firmware variable.
 */
static void
PrintVariable(const void *key, const void *value, void *context)
{
	if (CFGetTypeID(key) != CFStringGetTypeID()) {
		printf("Variable name passed in isn't a string");
		return;
	}
	long cnt, cnt2;
	CFIndex nameLen;
	char *nameBuffer = 0;
	const char *nameString;
	char numberBuffer[10];
	const uint8_t *dataPtr;
	uint8_t dataChar;
	char *dataBuffer = 0;
	CFIndex valueLen;
	char *valueBuffer = 0;
	const char *valueString = 0;
	uint32_t number;
	long length;
	CFTypeID typeID;
	// Get the variable's name.
	nameLen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(key), kCFStringEncodingUTF8) + 1;

	nameBuffer = malloc(nameLen);

	if (nameBuffer && CFStringGetCString(key, nameBuffer, nameLen, kCFStringEncodingUTF8)) {
		nameString = nameBuffer;
	} else {
		printf("Unable to convert property name to C string");
		nameString = "<UNPRINTABLE>";
	}

	// Get the variable's type.
	typeID = CFGetTypeID(value);

	if (typeID == CFBooleanGetTypeID()) {
		if (CFBooleanGetValue(value)) {
			valueString = "true";
		} else {
			valueString = "false";
		}
	} else if (typeID == CFNumberGetTypeID()) {
		CFNumberGetValue(value, kCFNumberSInt32Type, &number);
		if (number == 0xFFFFFFFF) {
			sprintf(numberBuffer, "-1");
		} else {
			sprintf(numberBuffer, "0x%x", number);
		}
		valueString = numberBuffer;
	} else if (typeID == CFStringGetTypeID()) {
		valueLen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value),
		    kCFStringEncodingUTF8) +
		    1;
		valueBuffer = malloc(valueLen + 1);
		if (valueBuffer && CFStringGetCString(value, valueBuffer, valueLen, kCFStringEncodingUTF8)) {
			valueString = valueBuffer;
		} else {
			printf("Unable to convert value to C string");
			valueString = "<UNPRINTABLE>";
		}
	} else if (typeID == CFDataGetTypeID()) {
		length = CFDataGetLength(value);
		if (length == 0) {
			valueString = "";
		} else {
			dataBuffer = malloc(length * NVRAM_BYTE_LEN + NVRAM_BYTE_LEN);
			if (dataBuffer != 0) {
				dataPtr = CFDataGetBytePtr(value);
				cnt = cnt2 = 0;
				for (; cnt < length; cnt++) {
					dataChar = dataPtr[cnt];
					if (isprint(dataChar) && dataChar != '%') {
						dataBuffer[cnt2++] = dataChar;
					} else {
						sprintf(dataBuffer + cnt2, "%%%02x", dataChar);
						cnt2 += NVRAM_BYTE_LEN;
					}
				}
				dataBuffer[cnt2] = '\0';
				valueString = dataBuffer;
			}
		}
	} else {
		valueString = "<INVALID>";
	}

	if ((nameString != 0) && (valueString != 0)) {
		printf("%s\t%s\n", nameString, valueString);
	}

	if (dataBuffer != 0) {
		free(dataBuffer);
	}
	if (nameBuffer != 0) {
		free(nameBuffer);
	}
	if (valueBuffer != 0) {
		free(valueBuffer);
	}
}

/**
 * @brief Convert the value into a CFType given the typeID
 */
static CFTypeRef
ConvertValueToCFTypeRef(CFTypeID typeID, const char *value)
{
	CFTypeRef valueRef = 0;
	long cnt, cnt2, length;
	unsigned long number, tmp;

	if (typeID == CFBooleanGetTypeID()) {
		if (value == NULL) {
			return valueRef;
		}
		if (!strcmp("true", value)) {
			valueRef = kCFBooleanTrue;
		} else if (!strcmp("false", value)) {
			valueRef = kCFBooleanFalse;
		}
	} else if (typeID == CFNumberGetTypeID()) {
		number = strtol(value, 0, 0);
		valueRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type,
		    &number);
	} else if (typeID == CFStringGetTypeID()) {
		valueRef = CFStringCreateWithCString(kCFAllocatorDefault, value,
		    kCFStringEncodingUTF8);
	} else if (typeID == CFDataGetTypeID()) {
		if (value == NULL) {
			length = 0;
		} else {
			length = strlen(value);
		}

		char valueCopy[length + 1];

		for (cnt = cnt2 = 0; cnt < length; cnt++, cnt2++) {
			if (value[cnt] == '%') {
				if ((cnt + 2 > length) ||
				    !ishexnumber(value[cnt + 1]) ||
				    !ishexnumber(value[cnt + 2])) {
					return 0;
				}
				number = toupper(value[++cnt]) - '0';
				if (number > 9) {
					number -= ASCII_OFFSET;
				}
				tmp = toupper(value[++cnt]) - '0';
				if (tmp > 9) {
					tmp -= ASCII_OFFSET;
				}
				number = (number << 4) + tmp;
				valueCopy[cnt2] = number;
			} else {
				valueCopy[cnt2] = value[cnt];
			}
		}
		valueRef = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)valueCopy, cnt2);
	} else {
		return 0;
	}

	return valueRef;
}

/**
 * @brief Prints the variable. returns kIOReturnNotFound if not found
 */
kern_return_t
GetVariable(const char *name, io_registry_entry_t optionsRef)
{
	CFStringRef nameRef = NULL;
	CFTypeRef valueRef = NULL;
	nameRef = CFStringCreateWithCString(kCFAllocatorDefault, name,
	    kCFStringEncodingUTF8);
	if (nameRef == 0) {
		printf("Error creating CFString for key %s", name);
		return KERN_FAILURE;
	}

	valueRef = IORegistryEntryCreateCFProperty(optionsRef, nameRef, 0, 0);
	if (valueRef == 0) {
		return kIOReturnNotFound;
	}

	PrintVariable(nameRef, valueRef, 0);

	return KERN_SUCCESS;
}

/**
 * @brief Set the named variable with the value passed in
 */
kern_return_t
SetVariable(const char *name, const char *value, io_registry_entry_t optionsRef)
{
	CFStringRef nameRef;
	CFTypeRef valueRef;
	CFTypeID typeID;
	kern_return_t result = KERN_FAILURE;

	nameRef = CFStringCreateWithCString(kCFAllocatorDefault, name,
	    kCFStringEncodingUTF8);
	if (nameRef == 0) {
		printf("Error creating CFString for key %s", name);
		return result;
	}

	valueRef = IORegistryEntryCreateCFProperty(optionsRef, nameRef, 0, 0);
	if (valueRef) {
		typeID = CFGetTypeID(valueRef);
		CFRelease(valueRef);
		valueRef = ConvertValueToCFTypeRef(typeID, value);
		if (valueRef == 0) {
			printf("Error creating CFTypeRef for value %s", value);
			return result;
		}
		result = IORegistryEntrySetCFProperty(optionsRef, nameRef, valueRef);
	} else {
		// skip testing different CFTypeIDs if there is no entry and it's a delete operation.
		if (value == NULL) {
			return result;
		}
		// In the default case, try data, string, number, then boolean.
		CFTypeID types[] = {CFDataGetTypeID(),
			            CFStringGetTypeID(), CFNumberGetTypeID(), CFBooleanGetTypeID()};
		for (int i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
			valueRef = ConvertValueToCFTypeRef(types[i], value);
			if (valueRef != 0) {
				result = IORegistryEntrySetCFProperty(optionsRef, nameRef, valueRef);
				if (result == KERN_SUCCESS || result == kIOReturnNoMemory || result == kIOReturnNoSpace) {
					break;
				}
			}
		}
	}

	CFRelease(nameRef);

	return result;
}

/**
 * @brief Delete named variable
 */
kern_return_t
DeleteVariable(const char *name, io_registry_entry_t optionsRef)
{
	// Since delete always returns ok, read to make sure it is deleted.
	if (SetVariable(kIONVRAMDeletePropertyKey, name, optionsRef) == KERN_SUCCESS) {
		if (GetVariable(name, optionsRef) == kIOReturnNotFound) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

/**
 * @brief Reset NVram
 */
kern_return_t
ResetNVram(io_registry_entry_t optionsRef)
{
	if (SetVariable("ResetNVRam", "1", optionsRef) == KERN_SUCCESS) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

/**
 * @brief Get the Options object
 */
io_registry_entry_t
GetOptions(void)
{
	io_registry_entry_t optionsRef = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options");
	T_ASSERT_NE(optionsRef, IO_OBJECT_NULL, "got options");
	return optionsRef;
}

/**
 * @brief Release option object passed in
 */
void
ReleaseOptions(io_registry_entry_t optionsRef)
{
	if (optionsRef != IO_OBJECT_NULL) {
		IOObjectRelease(optionsRef);
	}
}
