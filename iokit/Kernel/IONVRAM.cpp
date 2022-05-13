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

#define IOKIT_ENABLE_SHARED_PTR

#include <AssertMacros.h>
#include <IOKit/IOLib.h>
#include <IOKit/IONVRAM.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOBSD.h>
#include <kern/debug.h>
#include <sys/csr.h>

#define super IOService

OSDefineMetaClassAndStructors(IODTNVRAM, IOService);

class IONVRAMCHRPHandler;
class IONVRAMV3Handler;

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define MAX_VAR_NAME_SIZE     63

#define kCurrentGenerationCountKey "Generation"
#define kCurrentNVRAMVersionKey    "Version"

#define kNVRAMCommonUsedKey    "CommonUsed"
#define kNVRAMSystemUsedKey    "SystemUsed"

#define kIONVRAMPrivilege       kIOClientPrivilegeAdministrator

#define MIN_SYNC_NOW_INTERVAL 15*60 /* Minimum 15 Minutes interval mandated */

#if defined(DEBUG) || defined(DEVELOPMENT)
#define DEBUG_INFO(fmt, args...)                                                  \
({                                                                                \
	if (gNVRAMLogging)                                                        \
	IOLog("%s:%s:%u - " fmt, __FILE_NAME__, __FUNCTION__, __LINE__, ##args); \
})

#define DEBUG_ALWAYS(fmt, args...)                                                \
({                                                                                \
	IOLog("%s:%s:%u - " fmt, __FILE_NAME__, __FUNCTION__, __LINE__, ##args); \
})
#else
#define DEBUG_INFO(fmt, args...) (void)NULL
#define DEBUG_ALWAYS(fmt, args...) (void)NULL
#endif

#define DEBUG_ERROR DEBUG_ALWAYS

#define SAFE_TO_LOCK() (preemption_enabled() && !panic_active())

#define CONTROLLERLOCK()                     \
({                                           \
	if (SAFE_TO_LOCK())                  \
	        IOLockLock(_controllerLock); \
})

#define CONTROLLERUNLOCK()                     \
({                                             \
	if (SAFE_TO_LOCK())                    \
	        IOLockUnlock(_controllerLock); \
})

#define NVRAMREADLOCK()                       \
({                                            \
	if (SAFE_TO_LOCK())                   \
	        IORWLockRead(_variableLock);  \
})

#define NVRAMWRITELOCK()                      \
({                                            \
	if (SAFE_TO_LOCK())                   \
	        IORWLockWrite(_variableLock); \
})

#define NVRAMUNLOCK()                          \
({                                             \
	if (SAFE_TO_LOCK())                    \
	        IORWLockUnlock(_variableLock); \
})

#define NVRAMLOCKASSERTHELD()                                       \
({                                                                  \
	if (SAFE_TO_LOCK())                                         \
	        IORWLockAssert(_variableLock, kIORWLockAssertHeld); \
})

#define NVRAMLOCKASSERTEXCLUSIVE()                                   \
({                                                                   \
	if (SAFE_TO_LOCK())                                          \
	        IORWLockAssert(_variableLock, kIORWLockAssertWrite); \
})

enum NVRAMVersion {
	kNVRAMVersionUnknown,
	kNVRAMVersion1,       // Legacy, banks, 0x800 common partition size
	kNVRAMVersion2,       // V1 but with (0x2000 - sizeof(struct apple_nvram_header) - sizeof(struct chrp_nvram_header)) common region
	kNVRAMVersion3,       // New EFI based format
	kNVRAMVersionMax
};

// Guid for Apple System Boot variables
// 40A0DDD2-77F8-4392-B4A3-1E7304206516
UUID_DEFINE(gAppleSystemVariableGuid, 0x40, 0xA0, 0xDD, 0xD2, 0x77, 0xF8, 0x43, 0x92, 0xB4, 0xA3, 0x1E, 0x73, 0x04, 0x20, 0x65, 0x16);

// Apple NVRAM Variable namespace (APPLE_VENDOR_OS_VARIABLE_GUID)
// 7C436110-AB2A-4BBB-A880-FE41995C9F82
UUID_DEFINE(gAppleNVRAMGuid, 0x7C, 0x43, 0x61, 0x10, 0xAB, 0x2A, 0x4B, 0xBB, 0xA8, 0x80, 0xFE, 0x41, 0x99, 0x5C, 0x9F, 0x82);

static TUNABLE(bool, gNVRAMLogging, "nvram-log", false);
static bool gInternalBuild = false;

// allowlist variables from macboot that need to be set/get from system region if present
static const char * const gNVRAMSystemList[] = {
	"allow-root-hash-mismatch",
	"auto-boot",
	"auto-boot-halt-stage",
	"base-system-path",
	"boot-args",
	"boot-command",
	"boot-image",
	"bootdelay",
	"com.apple.System.boot-nonce",
	"darkboot",
	"emu",
	"one-time-boot-command", // Needed for diags customer install flows
	"policy-nonce-digests",
	"prevent-restores", // Keep for factory <rdar://problem/70476321>
	"prev-lang:kbd",
	"root-live-fs",
	"sep-debug-args", // Needed to simplify debug flows for SEP
	"StartupMute", // Set by customers via nvram tool
	"SystemAudioVolume",
	"SystemAudioVolumeExtension",
	"SystemAudioVolumeSaved",
	nullptr
};

typedef struct {
	const char *name;
	IONVRAMVariableType type;
} VariableTypeEntry;

static const
VariableTypeEntry gVariableTypes[] = {
	{"auto-boot?", kOFVariableTypeBoolean},
	{"boot-args", kOFVariableTypeString},
	{"boot-command", kOFVariableTypeString},
	{"boot-device", kOFVariableTypeString},
	{"boot-file", kOFVariableTypeString},
	{"boot-screen", kOFVariableTypeString},
	{"boot-script", kOFVariableTypeString},
	{"console-screen", kOFVariableTypeString},
	{"default-client-ip", kOFVariableTypeString},
	{"default-gateway-ip", kOFVariableTypeString},
	{"default-mac-address?", kOFVariableTypeBoolean},
	{"default-router-ip", kOFVariableTypeString},
	{"default-server-ip", kOFVariableTypeString},
	{"default-subnet-mask", kOFVariableTypeString},
	{"diag-device", kOFVariableTypeString},
	{"diag-file", kOFVariableTypeString},
	{"diag-switch?", kOFVariableTypeBoolean},
	{"fcode-debug?", kOFVariableTypeBoolean},
	{"input-device", kOFVariableTypeString},
	{"input-device-1", kOFVariableTypeString},
	{"little-endian?", kOFVariableTypeBoolean},
	{"load-base", kOFVariableTypeNumber},
	{"mouse-device", kOFVariableTypeString},
	{"nvramrc", kOFVariableTypeString},
	{"oem-banner", kOFVariableTypeString},
	{"oem-banner?", kOFVariableTypeBoolean},
	{"oem-logo", kOFVariableTypeString},
	{"oem-logo?", kOFVariableTypeBoolean},
	{"output-device", kOFVariableTypeString},
	{"output-device-1", kOFVariableTypeString},
	{"pci-probe-list", kOFVariableTypeNumber},
	{"pci-probe-mask", kOFVariableTypeNumber},
	{"real-base", kOFVariableTypeNumber},
	{"real-mode?", kOFVariableTypeBoolean},
	{"real-size", kOFVariableTypeNumber},
	{"screen-#columns", kOFVariableTypeNumber},
	{"screen-#rows", kOFVariableTypeNumber},
	{"security-mode", kOFVariableTypeString},
	{"selftest-#megs", kOFVariableTypeNumber},
	{"use-generic?", kOFVariableTypeBoolean},
	{"use-nvramrc?", kOFVariableTypeBoolean},
	{"virt-base", kOFVariableTypeNumber},
	{"virt-size", kOFVariableTypeNumber},

#if !defined(__x86_64__)
	{"acc-cm-override-charger-count", kOFVariableTypeNumber},
	{"acc-cm-override-count", kOFVariableTypeNumber},
	{"acc-mb-ld-lifetime", kOFVariableTypeNumber},
	{"com.apple.System.boot-nonce", kOFVariableTypeString},
	{"darkboot", kOFVariableTypeBoolean},
	{"enter-tdm-mode", kOFVariableTypeBoolean},
#endif /* !defined(__x86_64__) */
	{nullptr, kOFVariableTypeData} // Default type to return
};

union VariablePermission {
	struct {
		uint64_t UserWrite            :1;
		uint64_t RootRequired         :1;
		uint64_t KernelOnly           :1;
		uint64_t ResetNVRAMOnlyDelete :1;
		uint64_t NeverAllowedToDelete :1;
		uint64_t SystemReadHidden     :1;
		uint64_t FullAccess           :1;
		uint64_t Reserved:57;
	} Bits;
	uint64_t Uint64;
};

typedef struct {
	const char *name;
	VariablePermission p;
} VariablePermissionEntry;

static const
VariablePermissionEntry gVariablePermissions[] = {
	{"aapl,pci", .p.Bits.RootRequired = 1},
	{"battery-health", .p.Bits.RootRequired = 1,
	 .p.Bits.NeverAllowedToDelete = 1},
	{"boot-image", .p.Bits.UserWrite = 1},
	{"com.apple.System.fp-state", .p.Bits.KernelOnly = 1},
	{"fm-account-masked", .p.Bits.RootRequired = 1,
	 .p.Bits.NeverAllowedToDelete = 1},
	{"fm-activation-locked", .p.Bits.RootRequired = 1,
	 .p.Bits.NeverAllowedToDelete = 1},
	{"fm-spkeys", .p.Bits.RootRequired = 1,
	 .p.Bits.NeverAllowedToDelete = 1},
	{"fm-spstatus", .p.Bits.RootRequired = 1,
	 .p.Bits.NeverAllowedToDelete = 1},
	{"policy-nonce-digests", .p.Bits.ResetNVRAMOnlyDelete = 1}, // Deleting this via user triggered obliterate leave J273a unable to boot
	{"recoveryos-passcode-blob", .p.Bits.SystemReadHidden = 1},
	{"security-password", .p.Bits.RootRequired = 1},
	{"system-passcode-lock-blob", .p.Bits.SystemReadHidden = 1},

#if !defined(__x86_64__)
	{"acc-cm-override-charger-count", .p.Bits.KernelOnly = 1},
	{"acc-cm-override-count", .p.Bits.KernelOnly = 1},
	{"acc-mb-ld-lifetime", .p.Bits.KernelOnly = 1},
	{"backlight-level", .p.Bits.UserWrite = 1},
	{"backlight-nits", .p.Bits.UserWrite = 1},
	{"com.apple.System.boot-nonce", .p.Bits.KernelOnly = 1},
	{"com.apple.System.sep.art", .p.Bits.KernelOnly = 1},
	{"darkboot", .p.Bits.UserWrite = 1},
	{"nonce-seeds", .p.Bits.KernelOnly = 1},
#endif /* !defined(__x86_64__) */

	{nullptr, {.Bits.FullAccess = 1}} // Default access
};

static NVRAMPartitionType
getPartitionTypeForGUID(const uuid_t guid)
{
	if (uuid_compare(guid, gAppleSystemVariableGuid) == 0) {
		return kIONVRAMPartitionSystem;
	} else {
		return kIONVRAMPartitionCommon;
	}
}

static IONVRAMVariableType
getVariableType(const char *propName)
{
	const VariableTypeEntry *entry;

	entry = gVariableTypes;
	while (entry->name != nullptr) {
		if (strcmp(entry->name, propName) == 0) {
			break;
		}
		entry++;
	}

	return entry->type;
}

static IONVRAMVariableType
getVariableType(const OSSymbol *propSymbol)
{
	return getVariableType(propSymbol->getCStringNoCopy());
}

static VariablePermission
getVariablePermission(const char *propName)
{
	const VariablePermissionEntry *entry;

	entry = gVariablePermissions;
	while (entry->name != nullptr) {
		if (strcmp(entry->name, propName) == 0) {
			break;
		}
		entry++;
	}

	return entry->p;
}

static bool
variableInAllowList(const char *varName)
{
	unsigned int i = 0;

	while (gNVRAMSystemList[i] != nullptr) {
		if (strcmp(varName, gNVRAMSystemList[i]) == 0) {
			return true;
		}
		i++;
	}

	return false;
}

static bool
verifyWriteSizeLimit(const uuid_t varGuid, const char *variableName, size_t propDataSize)
{
	if (variableInAllowList(variableName)) {
		if (strnstr(variableName, "breadcrumbs", strlen(variableName)) != NULL) {
			return propDataSize <= 1024;
		} else {
			return propDataSize <= 768;
		}
	}

	return true;
}

#if defined(DEBUG) || defined(DEVELOPMENT)
static const char *
getNVRAMOpString(IONVRAMOperation op)
{
	switch (op) {
	case kIONVRAMOperationRead:
		return "Read";
	case kIONVRAMOperationWrite:
		return "Write";
	case kIONVRAMOperationDelete:
		return "Delete";
	case kIONVRAMOperationObliterate:
		return "Obliterate";
	case kIONVRAMOperationReset:
		return "Reset";
	case kIONVRAMOperationInit:
		return "Init";
	default:
		return "Unknown";
	}
}
#endif

static bool
verifyPermission(IONVRAMOperation op, const uuid_t varGuid, const char *varName)
{
	VariablePermission perm;
	bool kernel, writeEntitled = false, readEntitled = false, allowList, systemGuid = false, systemEntitled = false, systemInternalEntitled = false, systemAllow, systemReadHiddenAllow = false;
	bool admin = false;
	bool ok = false;

	perm = getVariablePermission(varName);

	kernel = current_task() == kernel_task;

	if (perm.Bits.KernelOnly) {
		DEBUG_INFO("KernelOnly access for %s, kernel=%d\n", varName, kernel);
		ok = kernel;
		goto exit;
	}

	allowList              = variableInAllowList(varName);
	systemGuid             = uuid_compare(varGuid, gAppleSystemVariableGuid) == 0;
	admin                  = IOUserClient::clientHasPrivilege(current_task(), kIONVRAMPrivilege) == kIOReturnSuccess;
	writeEntitled          = IOCurrentTaskHasEntitlement(kIONVRAMWriteAccessKey);
	readEntitled           = IOCurrentTaskHasEntitlement(kIONVRAMReadAccessKey);
	systemEntitled         = IOCurrentTaskHasEntitlement(kIONVRAMSystemAllowKey);
	systemInternalEntitled = IOCurrentTaskHasEntitlement(kIONVRAMSystemInternalAllowKey);
	systemReadHiddenAllow  = IOCurrentTaskHasEntitlement(kIONVRAMSystemHiddenAllowKey);

	systemAllow = systemEntitled || (systemInternalEntitled && gInternalBuild) || kernel;

	switch (op) {
	case kIONVRAMOperationRead:
		if (systemGuid && perm.Bits.SystemReadHidden) {
			ok = systemReadHiddenAllow;
		} else if (kernel || admin || readEntitled || perm.Bits.FullAccess) {
			ok = true;
		}
		break;

	case kIONVRAMOperationWrite:
		if (kernel || perm.Bits.UserWrite || admin || writeEntitled) {
			if (systemGuid) {
				if (allowList) {
					if (!systemAllow) {
						DEBUG_ERROR("Allowed write to system region when NOT entitled for %s\n", varName);
					}
				} else if (!systemAllow) {
					DEBUG_ERROR("Not entitled for system region writes for %s\n", varName);
					break;
				}
			}
			ok = true;
		}
		break;

	case kIONVRAMOperationDelete:
	case kIONVRAMOperationObliterate:
	case kIONVRAMOperationReset:
		if (perm.Bits.NeverAllowedToDelete) {
			DEBUG_INFO("Never allowed to delete %s\n", varName);
			break;
		} else if ((op == kIONVRAMOperationObliterate) && perm.Bits.ResetNVRAMOnlyDelete) {
			DEBUG_INFO("Not allowed to obliterate %s\n", varName);
			break;
		} else if ((op == kIONVRAMOperationDelete) && perm.Bits.ResetNVRAMOnlyDelete) {
			DEBUG_INFO("Only allowed to delete %s via NVRAM reset\n", varName);
			break;
		}

		if (kernel || perm.Bits.UserWrite || admin || writeEntitled) {
			if (systemGuid) {
				if (allowList) {
					if (!systemAllow) {
						DEBUG_ERROR("Allowed delete to system region when NOT entitled for %s\n", varName);
					}
				} else if (!systemAllow) {
					DEBUG_ERROR("Not entitled for system region deletes for %s\n", varName);
					break;
				}
			}
			ok = true;
		}
		break;

	case kIONVRAMOperationInit:
		break;
	}

exit:
	DEBUG_INFO("Permission for %s of %s %s: kern=%d, adm=%d, wE=%d, rE=%d, sG=%d, sEd=%d, sIEd=%d, sRHA=%d, UW=%d\n", getNVRAMOpString(op), varName, ok ? "granted" : "denied",
	    kernel, admin, writeEntitled, readEntitled, systemGuid, systemEntitled, systemInternalEntitled, systemReadHiddenAllow, perm.Bits.UserWrite);

	return ok;
}

static bool
verifyPermission(IONVRAMOperation op, const uuid_t varGuid, const OSSymbol *varName)
{
	return verifyPermission(op, varGuid, varName->getCStringNoCopy());
}

/*
 * Parse a variable name of the form "GUID:name".
 * If the name cannot be parsed, substitute the Apple global variable GUID.
 * Returns TRUE if a GUID was found in the name, FALSE otherwise.
 * The guidResult and nameResult arguments may be nullptr if you just want
 * to check the format of the string.
 */
static bool
parseVariableName(const char *key, uuid_t *guidResult, const char **nameResult)
{
	uuid_string_t temp    = {0};
	size_t        keyLen  = strlen(key);
	bool          ok      = false;
	const char    *name   = key;
	uuid_t        guid;

	if (keyLen > sizeof(temp)) {
		// check for at least UUID + ":" + more
		memcpy(temp, key, sizeof(temp) - 1);

		if ((uuid_parse(temp, guid) == 0) &&
		    (key[sizeof(temp) - 1] == ':')) {
			name = key + sizeof(temp);
			ok     = true;
		}
	}

	if (guidResult) {
		ok ? uuid_copy(*guidResult, guid) : uuid_copy(*guidResult, gAppleNVRAMGuid);
	}
	if (nameResult) {
		*nameResult = name;
	}

	return ok;
}

static bool
skipKey(const OSSymbol *aKey)
{
	return aKey->isEqualTo(kIOClassNameOverrideKey) ||
	       aKey->isEqualTo(kIOBSDNameKey) ||
	       aKey->isEqualTo(kIOBSDNamesKey) ||
	       aKey->isEqualTo(kIOBSDMajorKey) ||
	       aKey->isEqualTo(kIOBSDMinorKey) ||
	       aKey->isEqualTo(kIOBSDUnitKey) ||
	       aKey->isEqualTo(kIOUserServicePropertiesKey) ||
	       aKey->isEqualTo(kIOMatchCategoryKey);
}


// ************************** IODTNVRAMDiags ****************************

#define kIODTNVRAMDiagsStatsKey   "Stats"
#define kIODTNVRAMDiagsInitKey    "Init"
#define kIODTNVRAMDiagsReadKey    "Read"
#define kIODTNVRAMDiagsWriteKey   "Write"
#define kIODTNVRAMDiagsDeleteKey  "Delete"
#define kIODTNVRAMDiagsNameKey    "Name"
#define kIODTNVRAMDiagsSizeKey    "Size"
#define kIODTNVRAMDiagsPresentKey "Present"

// private IOService based class for publishing diagnostic info for IODTNVRAM
class IODTNVRAMDiags : public IOService
{
	OSDeclareDefaultStructors(IODTNVRAMDiags)
private:
	IODTNVRAM                 *_provider;
	IORWLock                  *_variableLock;
	OSSharedPtr<OSDictionary> _stats;

	bool serializeStats(void *, OSSerialize * serializer);

public:
	bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
	void logVariable(NVRAMPartitionType region, IONVRAMOperation op, const char *name, void *data);
};

OSDefineMetaClassAndStructors(IODTNVRAMDiags, IOService)

bool
IODTNVRAMDiags::start(IOService * provider)
{
	OSSharedPtr<OSSerializer> serializer;

	require(super::start(provider), error);

	_variableLock = IORWLockAlloc();
	require(_variableLock != nullptr, error);

	_provider = OSDynamicCast(IODTNVRAM, provider);
	require(_provider != nullptr, error);

	_stats = OSDictionary::withCapacity(1);
	require(_stats != nullptr, error);

	serializer = OSSerializer::forTarget(this, OSMemberFunctionCast(OSSerializerCallback, this, &IODTNVRAMDiags::serializeStats));
	require(serializer != nullptr, error);

	setProperty(kIODTNVRAMDiagsStatsKey, serializer.get());

	registerService();

	return true;

error:
	stop(provider);

	return false;
}

void
IODTNVRAMDiags::logVariable(NVRAMPartitionType region, IONVRAMOperation op, const char *name, void *data)
{
	// "Stats"        : OSDictionary
	// - "XX:varName" : OSDictionary, XX is the region value prefix to distinguish which dictionary the variable is in
	//   - "Init"     : OSBoolean True/present if variable present at initialization
	//   - "Read"     : OSNumber count
	//   - "Write"    : OSNumber count
	//   - "Delete"   : OSNumber count
	//   - "Size"     : OSNumber size, latest size from either init or write
	//   - "Present"  : OSBoolean True/False if variable is present or not
	char                      *entryKey;
	size_t                    entryKeySize;
	OSSharedPtr<OSDictionary> existingEntry;
	OSSharedPtr<OSNumber>     currentCount;
	OSSharedPtr<OSNumber>     varSize;
	const char                *opCountKey = nullptr;

	entryKeySize = strlen("XX:") + strlen(name) +  1;
	entryKey = IONewData(char, entryKeySize);
	require(entryKey, exit);

	snprintf(entryKey, entryKeySize, "%02X:%s", region, name);

	NVRAMWRITELOCK();
	existingEntry.reset(OSDynamicCast(OSDictionary, _stats->getObject(entryKey)), OSRetain);

	if (existingEntry == nullptr) {
		existingEntry = OSDictionary::withCapacity(4);
	}

	switch (op) {
	case kIONVRAMOperationRead:
		opCountKey = kIODTNVRAMDiagsReadKey;
		if (existingEntry->getObject(kIODTNVRAMDiagsPresentKey) == nullptr) {
			existingEntry->setObject(kIODTNVRAMDiagsPresentKey, kOSBooleanFalse);
		}
		break;
	case kIONVRAMOperationWrite:
		opCountKey = kIODTNVRAMDiagsWriteKey;
		varSize = OSNumber::withNumber((size_t)data, 64);
		existingEntry->setObject(kIODTNVRAMDiagsSizeKey, varSize);
		existingEntry->setObject(kIODTNVRAMDiagsPresentKey, kOSBooleanTrue);
		break;
	case kIONVRAMOperationDelete:
	case kIONVRAMOperationObliterate:
	case kIONVRAMOperationReset:
		opCountKey = kIODTNVRAMDiagsDeleteKey;
		existingEntry->setObject(kIODTNVRAMDiagsPresentKey, kOSBooleanFalse);
		break;
	case kIONVRAMOperationInit:
		varSize = OSNumber::withNumber((size_t)data, 64);
		existingEntry->setObject(kIODTNVRAMDiagsInitKey, varSize);
		existingEntry->setObject(kIODTNVRAMDiagsSizeKey, varSize);
		existingEntry->setObject(kIODTNVRAMDiagsPresentKey, kOSBooleanTrue);
		break;
	default:
		goto exit;
	}

	if (opCountKey) {
		currentCount.reset(OSDynamicCast(OSNumber, existingEntry->getObject(opCountKey)), OSRetain);

		if (currentCount == nullptr) {
			currentCount = OSNumber::withNumber(1, 64);
		} else {
			currentCount->addValue(1);
		}

		existingEntry->setObject(opCountKey, currentCount);
	}

	_stats->setObject(entryKey, existingEntry);
	NVRAMUNLOCK();

exit:
	IODeleteData(entryKey, char, entryKeySize);

	return;
}

bool
IODTNVRAMDiags::serializeStats(void *, OSSerialize * serializer)
{
	bool ok;

	NVRAMREADLOCK();
	ok = _stats->serialize(serializer);
	NVRAMUNLOCK();

	return ok;
}

// ************************** IODTNVRAMVariables ****************************

// private IOService based class for publishing distinct dictionary properties on
// for easy ioreg access since the serializeProperties call is overloaded and is used
// as variable access
class IODTNVRAMVariables : public IOService
{
	OSDeclareDefaultStructors(IODTNVRAMVariables)
private:
	IODTNVRAM        *_provider;
	uuid_t           _guid;

public:
	bool                    init(const uuid_t guid);
	virtual bool            start(IOService * provider) APPLE_KEXT_OVERRIDE;

	virtual bool            serializeProperties(OSSerialize *s) const APPLE_KEXT_OVERRIDE;
	virtual OSPtr<OSObject> copyProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSObject        *getProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual bool            setProperty(const OSSymbol *aKey, OSObject *anObject) APPLE_KEXT_OVERRIDE;
	virtual IOReturn        setProperties(OSObject *properties) APPLE_KEXT_OVERRIDE;
	virtual void            removeProperty(const OSSymbol *aKey) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(IODTNVRAMVariables, IOService)

bool
IODTNVRAMVariables::init(const uuid_t guid)
{
	require(super::init(), fail);

	uuid_copy(_guid, guid);

	return true;

fail:
	return false;
}

bool
IODTNVRAMVariables::start(IOService * provider)
{
	if (!super::start(provider)) {
		goto error;
	}

	_provider = OSDynamicCast(IODTNVRAM, provider);
	if (_provider == nullptr) {
		goto error;
	}

	registerService();

	return true;

error:
	stop(provider);

	return false;
}

bool
IODTNVRAMVariables::serializeProperties(OSSerialize *s) const
{
	const OSSymbol                    *key;
	OSSharedPtr<OSDictionary>         dict;
	OSSharedPtr<OSCollectionIterator> iter;
	OSSharedPtr<OSDictionary>         localVariables;
	bool                              ok = false;
	bool                              systemGuid = uuid_compare(_guid, gAppleSystemVariableGuid) == 0;

	if (systemGuid) {
		localVariables = _provider->_systemDict;
	} else {
		localVariables = _provider->_commonDict;
	}

	if (localVariables == nullptr) {
		goto exit;
	}

	dict = OSDictionary::withCapacity(localVariables->getCount());
	if (dict == nullptr) {
		DEBUG_ERROR("No dictionary\n");
		goto exit;
	}

	iter = OSCollectionIterator::withCollection(localVariables.get());
	if (iter == nullptr) {
		DEBUG_ERROR("failed to create iterator\n");
		goto exit;
	}

	while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
		if (verifyPermission(kIONVRAMOperationRead, _guid, key)) {
			dict->setObject(key, localVariables->getObject(key));
		}
	}

	ok = dict->serialize(s);

exit:
	DEBUG_INFO("ok=%d\n", ok);
	return ok;
}

OSPtr<OSObject>
IODTNVRAMVariables::copyProperty(const OSSymbol *aKey) const
{
	if (_provider && !skipKey(aKey)) {
		DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

		return _provider->copyPropertyWithGUIDAndName(_guid, aKey->getCStringNoCopy());
	} else {
		return nullptr;
	}
}

OSObject *
IODTNVRAMVariables::getProperty(const OSSymbol *aKey) const
{
	OSSharedPtr<OSObject> theObject = copyProperty(aKey);

	return theObject.get();
}

bool
IODTNVRAMVariables::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
	if (_provider) {
		return _provider->setPropertyWithGUIDAndName(_guid, aKey->getCStringNoCopy(), anObject) == kIOReturnSuccess;
	} else {
		return false;
	}
}

IOReturn
IODTNVRAMVariables::setProperties(OSObject *properties)
{
	IOReturn                          ret = kIOReturnSuccess;
	OSObject                          *object;
	const OSSymbol                    *key;
	OSDictionary                      *dict;
	OSSharedPtr<OSCollectionIterator> iter;

	if (_provider) {
		dict = OSDynamicCast(OSDictionary, properties);
		if (dict == nullptr) {
			DEBUG_ERROR("Not a dictionary\n");
			return kIOReturnBadArgument;
		}

		iter = OSCollectionIterator::withCollection(dict);
		if (iter == nullptr) {
			DEBUG_ERROR("Couldn't create iterator\n");
			return kIOReturnBadArgument;
		}

		while (ret == kIOReturnSuccess) {
			key = OSDynamicCast(OSSymbol, iter->getNextObject());
			if (key == nullptr) {
				break;
			}

			object = dict->getObject(key);
			if (object == nullptr) {
				continue;
			}

			ret = _provider->setPropertyWithGUIDAndName(_guid, key->getCStringNoCopy(), object);
		}
	} else {
		ret = kIOReturnNotReady;
	}

	DEBUG_INFO("ret=%#08x\n", ret);

	return ret;
}

void
IODTNVRAMVariables::removeProperty(const OSSymbol *aKey)
{
	if (_provider) {
		_provider->removePropertyWithGUIDAndName(_guid, aKey->getCStringNoCopy());
	}
}

// ************************** Format Handlers ***************************

IODTNVRAMFormatHandler::~IODTNVRAMFormatHandler()
{
}

#include "IONVRAMCHRPHandler.cpp"

#include "IONVRAMV3Handler.cpp"

// **************************** IODTNVRAM *********************************

bool
IODTNVRAM::init(IORegistryEntry *old, const IORegistryPlane *plane)
{
	OSSharedPtr<OSDictionary> dict;

	DEBUG_INFO("...\n");

	require(super::init(old, plane), fail);

#if XNU_TARGET_OS_OSX
#if CONFIG_CSR
	gInternalBuild = (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0);
	DEBUG_INFO("gInternalBuild = %d\n", gInternalBuild);
#endif // CONFIG_CSR
#endif // XNU_TARGET_OS_OSX

	_variableLock = IORWLockAlloc();
	require(_variableLock != nullptr, fail);

	_controllerLock = IOLockAlloc();
	require(_controllerLock != nullptr, fail);

	// Clear the IORegistryEntry property table
	dict =  OSDictionary::withCapacity(1);
	require(dict != nullptr, fail);

	setPropertyTable(dict.get());
	dict.reset();

	return true;

fail:
	return false;
}

bool
IODTNVRAM::start(IOService *provider)
{
	OSSharedPtr<OSNumber> version;

	DEBUG_INFO("...\n");

	require(super::start(provider), fail);

	// Check if our overridden init function was called
	// If not, skip any additional initialization being done here.
	// This is not an error we just need to successfully exit this function to allow
	// AppleEFIRuntime to proceed and take over operation
	require_action(_controllerLock != nullptr, no_common, DEBUG_INFO("x86 init\n"));

	_diags = new IODTNVRAMDiags;
	if (!_diags || !_diags->init()) {
		DEBUG_ERROR("Unable to create/init the diags service\n");
		OSSafeReleaseNULL(_diags);
		goto fail;
	}

	if (!_diags->attach(this)) {
		DEBUG_ERROR("Unable to attach the diags service!\n");
		OSSafeReleaseNULL(_diags);
		goto fail;
	}

	if (!_diags->start(this)) {
		DEBUG_ERROR("Unable to start the diags service!\n");
		_diags->detach(this);
		OSSafeReleaseNULL(_diags);
		goto fail;
	}

	// This will load the proxied variable data which will call back into
	// IODTNVRAM for the variable sets which will also update the system/common services
	initImageFormat();

	version = OSNumber::withNumber(_format->getVersion(), 32);
	_diags->setProperty(kCurrentNVRAMVersionKey, version.get());

	if (_format->getSystemUsed()) {
		_systemService = new IODTNVRAMVariables;

		if (!_systemService || !_systemService->init(gAppleSystemVariableGuid)) {
			DEBUG_ERROR("Unable to start the system service!\n");
			OSSafeReleaseNULL(_systemService);
			goto no_system;
		}

		_systemService->setName("options-system");

		if (!_systemService->attach(this)) {
			DEBUG_ERROR("Unable to attach the system service!\n");
			OSSafeReleaseNULL(_systemService);
			goto no_system;
		}

		if (!_systemService->start(this)) {
			DEBUG_ERROR("Unable to start the system service!\n");
			_systemService->detach(this);
			OSSafeReleaseNULL(_systemService);
			goto no_system;
		}
	}

no_system:
	_commonService = new IODTNVRAMVariables;

	if (!_commonService || !_commonService->init(gAppleNVRAMGuid)) {
		DEBUG_ERROR("Unable to start the common service!\n");
		OSSafeReleaseNULL(_commonService);
		goto no_common;
	}

	_commonService->setName("options-common");

	if (!_commonService->attach(this)) {
		DEBUG_ERROR("Unable to attach the common service!\n");
		OSSafeReleaseNULL(_commonService);
		goto no_common;
	}

	if (!_commonService->start(this)) {
		DEBUG_ERROR("Unable to start the common service!\n");
		_commonService->detach(this);
		OSSafeReleaseNULL(_commonService);
		goto no_common;
	}

no_common:
	return true;

fail:
	stop(provider);
	return false;
}

void
IODTNVRAM::initImageFormat(void)
{
	OSSharedPtr<IORegistryEntry> entry;
	OSSharedPtr<OSObject>        prop;
	const char                   *proxyDataKey = "nvram-proxy-data";
	const char                   *bankSizeKey = "nvram-bank-size";
	OSData                       *data;
	uint32_t                     size = 0;

	entry = IORegistryEntry::fromPath("/chosen", gIODTPlane);

	require(entry != nullptr, skip);

	prop = entry->copyProperty(bankSizeKey);
	require(prop != nullptr, skip);

	data = OSDynamicCast(OSData, prop.get());
	require(data != nullptr, skip);

	size = *((uint32_t*)data->getBytesNoCopy());
	DEBUG_ALWAYS("NVRAM size is %u bytes\n", size);

	prop = entry->copyProperty(proxyDataKey);
	require(prop != nullptr, skip);

	data = OSDynamicCast(OSData, prop.get());
	require(data != nullptr, skip);

	if (IONVRAMV3Handler::isValidImage((const uint8_t *)data->getBytesNoCopy(), size)) {
		_format = IONVRAMV3Handler::init(this, (const uint8_t *)data->getBytesNoCopy(), size, _commonDict, _systemDict);
		require_action(_format, skip, panic("IONVRAMV3Handler creation failed\n"));
	} else {
		_format = IONVRAMCHRPHandler::init(this, (const uint8_t *)data->getBytesNoCopy(), size, _commonDict, _systemDict);
		require_action(_format, skip, panic("IONVRAMCHRPHandler creation failed\n"));
	}

#if defined(RELEASE)
	if (entry != nullptr) {
		entry->removeProperty(proxyDataKey);
	}
#endif

skip:
	_lastDeviceSync = 0;
	_freshInterval = true;
}

void
IODTNVRAM::registerNVRAMController(IONVRAMController *controller)
{
	DEBUG_INFO("setting controller\n");

	NVRAMWRITELOCK();
	CONTROLLERLOCK();

	_format->setController(controller);

	CONTROLLERUNLOCK();
	NVRAMUNLOCK();

	return;
}

bool
IODTNVRAM::safeToSync(void)
{
	AbsoluteTime delta;
	UInt64       delta_ns;
	SInt32       delta_secs;

	// delta interval went by
	clock_get_uptime(&delta);

	// Figure it in seconds.
	absolutetime_to_nanoseconds(delta, &delta_ns);
	delta_secs = (SInt32)(delta_ns / NSEC_PER_SEC);

	if ((delta_secs > (_lastDeviceSync + MIN_SYNC_NOW_INTERVAL)) || _freshInterval) {
		_lastDeviceSync = delta_secs;
		_freshInterval = false;
		return true;
	}

	return false;
}

void
IODTNVRAM::syncInternal(bool rateLimit)
{
	DEBUG_INFO("rateLimit=%d\n", rateLimit);

	if (!SAFE_TO_LOCK()) {
		DEBUG_INFO("cannot lock\n");
		return;
	}

	// Rate limit requests to sync. Drivers that need this rate limiting will
	// shadow the data and only write to flash when they get a sync call
	if (rateLimit) {
		if (safeToSync() == false) {
			DEBUG_INFO("safeToSync()=false\n");
			return;
		}
	}

	DEBUG_INFO("Calling sync()\n");

	NVRAMREADLOCK();
	CONTROLLERLOCK();

	_format->sync();

	CONTROLLERUNLOCK();
	NVRAMUNLOCK();

	if (_diags) {
		OSSharedPtr<OSNumber> generation = OSNumber::withNumber(_format->getGeneration(), 32);
		_diags->setProperty(kCurrentGenerationCountKey, generation.get());
	}
}

void
IODTNVRAM::sync(void)
{
	syncInternal(false);
}

bool
IODTNVRAM::serializeProperties(OSSerialize *s) const
{
	const OSSymbol                    *key;
	OSSharedPtr<OSDictionary>         systemDict, commonDict, dict;
	OSSharedPtr<OSCollectionIterator> iter;
	bool                              ok = false;
	unsigned int                      totalCapacity = 0;

	NVRAMREADLOCK();
	if (_commonDict) {
		commonDict = OSDictionary::withDictionary(_commonDict.get());
	}

	if (_systemDict) {
		systemDict = OSDictionary::withDictionary(_systemDict.get());
	}
	NVRAMUNLOCK();

	totalCapacity += (commonDict != nullptr) ? commonDict->getCapacity() : 0;
	totalCapacity += (systemDict != nullptr) ? systemDict->getCapacity() : 0;

	dict = OSDictionary::withCapacity(totalCapacity);

	if (dict == nullptr) {
		DEBUG_ERROR("No dictionary\n");
		goto exit;
	}

	// Copy system entries first if present then copy unique common entries
	if (systemDict != nullptr) {
		iter = OSCollectionIterator::withCollection(systemDict.get());
		if (iter == nullptr) {
			DEBUG_ERROR("failed to create iterator\n");
			goto exit;
		}

		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (verifyPermission(kIONVRAMOperationRead, gAppleSystemVariableGuid, key)) {
				dict->setObject(key, systemDict->getObject(key));
			}
		}

		iter.reset();
	}

	if (commonDict != nullptr) {
		iter = OSCollectionIterator::withCollection(commonDict.get());
		if (iter == nullptr) {
			DEBUG_ERROR("failed to create common iterator\n");
			goto exit;
		}

		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (dict->getObject(key) != nullptr) {
				// Skip non uniques
				continue;
			}
			if (verifyPermission(kIONVRAMOperationRead, gAppleNVRAMGuid, key)) {
				dict->setObject(key, commonDict->getObject(key));
			}
		}
	}

	ok = dict->serialize(s);

exit:
	DEBUG_INFO("ok=%d\n", ok);

	return ok;
}

NVRAMPartitionType
IODTNVRAM::getDictionaryType(const OSDictionary *dict) const
{
	if (dict == _commonDict) {
		return kIONVRAMPartitionCommon;
	} else if (dict == _systemDict) {
		return kIONVRAMPartitionSystem;
	} else {
		return kIONVRAMPartitionTypeUnknown;
	}
}

IOReturn
IODTNVRAM::chooseDictionary(IONVRAMOperation operation, const uuid_t varGuid, const char *variableName, OSDictionary **dict) const
{
	if (_systemDict != nullptr) {
		bool systemGuid = uuid_compare(varGuid, gAppleSystemVariableGuid) == 0;

		if (variableInAllowList(variableName)) {
			DEBUG_INFO("Using system dictionary due to allow list\n");
			if (!systemGuid) {
				DEBUG_ERROR("System GUID NOT used for %s\n", variableName);
			}
			*dict = _systemDict.get();
		} else if (systemGuid) {
			DEBUG_INFO("Using system dictionary via GUID\n");
			*dict = _systemDict.get();
		} else {
			DEBUG_INFO("Using common dictionary\n");
			*dict = _commonDict.get();
		}
		return kIOReturnSuccess;
	} else if (_commonDict != nullptr) {
		DEBUG_INFO("Defaulting to common dictionary\n");
		*dict = _commonDict.get();
		return kIOReturnSuccess;
	}

	return kIOReturnNotFound;
}

IOReturn
IODTNVRAM::flushDict(const uuid_t guid, IONVRAMOperation op)
{
	IOReturn ret = kIOReturnSuccess;

	if ((_systemDict != nullptr) && (uuid_compare(guid, gAppleSystemVariableGuid) == 0)) {
		ret = _format->flush(guid, op);

		DEBUG_INFO("system dictionary flushed, ret=%08x\n", ret);
	} else if ((_commonDict != nullptr) && (uuid_compare(guid, gAppleNVRAMGuid) == 0)) {
		ret = _format->flush(guid, op);

		DEBUG_INFO("common dictionary flushed, ret=%08x\n", ret);
	}

	return ret;
}

bool
IODTNVRAM::handleSpecialVariables(const char *name, const uuid_t guid, const OSObject *obj, IOReturn *error)
{
	IOReturn ret = kIOReturnSuccess;
	bool special = false;

	NVRAMLOCKASSERTEXCLUSIVE();

	// ResetNVRam flushes both regions in one call
	// Obliterate can flush either separately
	if (strcmp(name, "ObliterateNVRam") == 0) {
		special = true;
		ret = flushDict(guid, kIONVRAMOperationObliterate);
	} else if (strcmp(name, "ResetNVRam") == 0) {
		special = true;
		ret = flushDict(gAppleSystemVariableGuid, kIONVRAMOperationReset);

		if (ret != kIOReturnSuccess) {
			goto exit;
		}

		ret = flushDict(gAppleNVRAMGuid, kIONVRAMOperationReset);
	}

exit:
	if (error) {
		*error = ret;
	}

	return special;
}

OSSharedPtr<OSObject>
IODTNVRAM::copyPropertyWithGUIDAndName(const uuid_t guid, const char *name) const
{
	IOReturn              result;
	OSDictionary          *dict;
	OSSharedPtr<OSObject> theObject = nullptr;

	result = chooseDictionary(kIONVRAMOperationRead, guid, name, &dict);
	if (result != kIOReturnSuccess) {
		DEBUG_INFO("No dictionary\n");
		goto exit;
	}

	if (!verifyPermission(kIONVRAMOperationRead, guid, name)) {
		DEBUG_INFO("Not privileged\n");
		goto exit;
	}

	NVRAMREADLOCK();
	theObject.reset(dict->getObject(name), OSRetain);
	NVRAMUNLOCK();

	if (_diags) {
		_diags->logVariable(getDictionaryType(dict), kIONVRAMOperationRead, name, NULL);
	}

	if (theObject != nullptr) {
		DEBUG_INFO("found data\n");
	}

exit:
	return theObject;
}

OSSharedPtr<OSObject>
IODTNVRAM::copyProperty(const OSSymbol *aKey) const
{
	const char            *variableName;
	uuid_t                varGuid;

	if (skipKey(aKey)) {
		return nullptr;
	}
	DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

	parseVariableName(aKey->getCStringNoCopy(), &varGuid, &variableName);

	return copyPropertyWithGUIDAndName(varGuid, variableName);
}

OSSharedPtr<OSObject>
IODTNVRAM::copyProperty(const char *aKey) const
{
	OSSharedPtr<const OSSymbol> keySymbol;
	OSSharedPtr<OSObject>       theObject;

	keySymbol = OSSymbol::withCString(aKey);
	if (keySymbol != nullptr) {
		theObject = copyProperty(keySymbol.get());
	}

	return theObject;
}

OSObject *
IODTNVRAM::getProperty(const OSSymbol *aKey) const
{
	// The shared pointer gets released at the end of the function,
	// and returns a view into theObject.
	OSSharedPtr<OSObject> theObject = copyProperty(aKey);

	return theObject.get();
}

OSObject *
IODTNVRAM::getProperty(const char *aKey) const
{
	// The shared pointer gets released at the end of the function,
	// and returns a view into theObject.
	OSSharedPtr<OSObject> theObject = copyProperty(aKey);

	return theObject.get();
}

IOReturn
IODTNVRAM::setPropertyWithGUIDAndName(const uuid_t guid, const char *name, OSObject *anObject)
{
	IOReturn              ret = kIOReturnSuccess;
	bool                  remove = false;
	OSString              *tmpString = nullptr;
	OSSharedPtr<OSObject> propObject;
	OSSharedPtr<OSObject> sharedObject(anObject, OSRetain);
	bool                  deletePropertyKey, syncNowPropertyKey, forceSyncNowPropertyKey;
	bool                  ok;
	size_t                propDataSize = 0;

	deletePropertyKey = strncmp(name, kIONVRAMDeletePropertyKey, sizeof(kIONVRAMDeletePropertyKey)) == 0;
	syncNowPropertyKey = strncmp(name, kIONVRAMSyncNowPropertyKey, sizeof(kIONVRAMSyncNowPropertyKey)) == 0;
	forceSyncNowPropertyKey = strncmp(name, kIONVRAMForceSyncNowPropertyKey, sizeof(kIONVRAMForceSyncNowPropertyKey)) == 0;

	if (deletePropertyKey) {
		tmpString = OSDynamicCast(OSString, anObject);
		if (tmpString != nullptr) {
			const char *variableName;
			uuid_t     valueVarGuid;
			bool       guidProvided;
			IOReturn   removeRet;

			guidProvided = parseVariableName(tmpString->getCStringNoCopy(), &valueVarGuid, &variableName);

			// nvram tool will provide a "nvram -d var" or "nvram -d guid:var" as
			// kIONVRAMDeletePropertyKey=var or kIONVRAMDeletePropertyKey=guid:var
			// that will come into this function as (gAppleNVRAMGuid, varname, nullptr)
			// if we provide the "-z" flag to the nvram tool this function will come in as
			// (gAppleSystemVariableGuid, varname, nullptr). We are reparsing the value string,
			// if there is a GUID provided with the value then use that GUID otherwise use the
			// guid that was provided via the node selection or default.
			if (guidProvided == false) {
				DEBUG_INFO("Removing with API provided GUID\n");
				removeRet = removePropertyWithGUIDAndName(guid, variableName);
			} else {
				DEBUG_INFO("Removing with value provided GUID\n");
				removeRet = removePropertyWithGUIDAndName(valueVarGuid, variableName);
			}

			DEBUG_INFO("kIONVRAMDeletePropertyKey found, removeRet=%#08x\n", removeRet);
		} else {
			DEBUG_INFO("kIONVRAMDeletePropertyKey value needs to be an OSString\n");
			ret = kIOReturnError;
		}
		goto exit;
	} else if (syncNowPropertyKey || forceSyncNowPropertyKey) {
		tmpString = OSDynamicCast(OSString, anObject);
		DEBUG_INFO("NVRAM sync key %s found\n", name);
		if (tmpString != nullptr) {
			// We still want to throttle NVRAM commit rate for SyncNow. ForceSyncNow is provided as a really big hammer.
			syncInternal(syncNowPropertyKey);
		} else {
			DEBUG_INFO("%s value needs to be an OSString\n", name);
			ret = kIOReturnError;
		}
		goto exit;
	}

	if (!verifyPermission(kIONVRAMOperationWrite, guid, name)) {
		DEBUG_INFO("Not privileged\n");
		ret = kIOReturnNotPrivileged;
		goto exit;
	}

	// Make sure the object is of the correct type.
	switch (getVariableType(name)) {
	case kOFVariableTypeBoolean:
		propObject = OSDynamicPtrCast<OSBoolean>(sharedObject);
		break;

	case kOFVariableTypeNumber:
		propObject = OSDynamicPtrCast<OSNumber>(sharedObject);
		break;

	case kOFVariableTypeString:
		propObject = OSDynamicPtrCast<OSString>(sharedObject);
		if (propObject != nullptr) {
			propDataSize = (OSDynamicPtrCast<OSString>(propObject))->getLength();

			if ((strncmp(name, kIONVRAMBootArgsKey, sizeof(kIONVRAMBootArgsKey)) == 0) && (propDataSize >= BOOT_LINE_LENGTH)) {
				DEBUG_ERROR("boot-args size too large for BOOT_LINE_LENGTH, propDataSize=%zu\n", propDataSize);
				ret = kIOReturnNoSpace;
				goto exit;
			}
		}
		break;

	case kOFVariableTypeData:
		propObject = OSDynamicPtrCast<OSData>(sharedObject);
		if (propObject == nullptr) {
			tmpString = OSDynamicCast(OSString, sharedObject.get());
			if (tmpString != nullptr) {
				propObject = OSData::withBytes(tmpString->getCStringNoCopy(),
				    tmpString->getLength());
			}
		}

		if (propObject != nullptr) {
			propDataSize = (OSDynamicPtrCast<OSData>(propObject))->getLength();
		}

#if defined(XNU_TARGET_OS_OSX)
		if ((propObject != nullptr) && ((OSDynamicPtrCast<OSData>(propObject))->getLength() == 0)) {
			remove = true;
		}
#endif /* defined(XNU_TARGET_OS_OSX) */
		break;
	default:
		break;
	}

	if (propObject == nullptr) {
		DEBUG_INFO("No property object\n");
		ret = kIOReturnBadArgument;
		goto exit;
	}

	if (!verifyWriteSizeLimit(guid, name, propDataSize)) {
		DEBUG_ERROR("Property data size of %zu too long for %s\n", propDataSize, name);
		ret = kIOReturnNoSpace;
		goto exit;
	}

	NVRAMWRITELOCK();
	ok = handleSpecialVariables(name, guid, propObject.get(), &ret);
	NVRAMUNLOCK();

	if (ok) {
		goto exit;
	}

	if (remove == false) {
		DEBUG_INFO("Adding object\n");
		NVRAMWRITELOCK();
		ret = _format->setVariable(guid, name, propObject.get());
		NVRAMUNLOCK();
	} else {
		DEBUG_INFO("Removing object\n");
		ret = removePropertyWithGUIDAndName(guid, name);
	}

	if (tmpString) {
		propObject.reset();
	}

exit:
	DEBUG_INFO("ret=%#08x\n", ret);

	return ret;
}

IOReturn
IODTNVRAM::setPropertyInternal(const OSSymbol *aKey, OSObject *anObject)
{
	const char *variableName;
	uuid_t     varGuid;

	DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

	parseVariableName(aKey->getCStringNoCopy(), &varGuid, &variableName);

	return setPropertyWithGUIDAndName(varGuid, variableName, anObject);
}

bool
IODTNVRAM::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
	return setPropertyInternal(aKey, anObject) == kIOReturnSuccess;
}

void
IODTNVRAM::removeProperty(const OSSymbol *aKey)
{
	IOReturn ret;

	ret = removePropertyInternal(aKey);

	if (ret != kIOReturnSuccess) {
		DEBUG_INFO("removePropertyInternal failed, ret=%#08x\n", ret);
	}
}

IOReturn
IODTNVRAM::removePropertyWithGUIDAndName(const uuid_t guid, const char *name)
{
	IOReturn      ret = kIOReturnSuccess;
	uuid_string_t uuidString;

	uuid_unparse(guid, uuidString);

	DEBUG_INFO("%s:%s\n", uuidString, name);

	if (!verifyPermission(kIONVRAMOperationDelete, guid, name)) {
		DEBUG_INFO("Not priveleged\n");
		ret = kIOReturnNotPrivileged;
		goto exit;
	}

	NVRAMWRITELOCK();

	if (_format->setVariable(guid, name, nullptr) != kIOReturnSuccess) {
		DEBUG_INFO("%s not found\n", name);
		ret = kIOReturnNotFound;
	}

	NVRAMUNLOCK();

exit:
	return ret;
}

IOReturn
IODTNVRAM::removePropertyInternal(const OSSymbol *aKey)
{
	IOReturn   ret;
	const char *variableName;
	uuid_t     varGuid;

	DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

	parseVariableName(aKey->getCStringNoCopy(), &varGuid, &variableName);

	ret = removePropertyWithGUIDAndName(varGuid, variableName);

	return ret;
}

IOReturn
IODTNVRAM::setProperties(OSObject *properties)
{
	IOReturn                          ret = kIOReturnSuccess;
	OSObject                          *object;
	const OSSymbol                    *key;
	OSDictionary                      *dict;
	OSSharedPtr<OSCollectionIterator> iter;

	dict = OSDynamicCast(OSDictionary, properties);
	if (dict == nullptr) {
		DEBUG_ERROR("Not a dictionary\n");
		return kIOReturnBadArgument;
	}

	iter = OSCollectionIterator::withCollection(dict);
	if (iter == nullptr) {
		DEBUG_ERROR("Couldn't create iterator\n");
		return kIOReturnBadArgument;
	}

	while (ret == kIOReturnSuccess) {
		key = OSDynamicCast(OSSymbol, iter->getNextObject());
		if (key == nullptr) {
			break;
		}

		object = dict->getObject(key);
		if (object == nullptr) {
			continue;
		}

		ret = setPropertyInternal(key, object);
	}

	DEBUG_INFO("ret=%#08x\n", ret);

	return ret;
}

// ********************** Deprecated ********************

IOReturn
IODTNVRAM::readXPRAM(IOByteCount offset, uint8_t *buffer,
    IOByteCount length)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::writeXPRAM(IOByteCount offset, uint8_t *buffer,
    IOByteCount length)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::readNVRAMProperty(IORegistryEntry *entry,
    const OSSymbol **name,
    OSData **value)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::writeNVRAMProperty(IORegistryEntry *entry,
    const OSSymbol *name,
    OSData *value)
{
	return kIOReturnUnsupported;
}

OSDictionary *
IODTNVRAM::getNVRAMPartitions(void)
{
	return NULL;
}

IOReturn
IODTNVRAM::readNVRAMPartition(const OSSymbol *partitionID,
    IOByteCount offset, uint8_t *buffer,
    IOByteCount length)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::writeNVRAMPartition(const OSSymbol *partitionID,
    IOByteCount offset, uint8_t *buffer,
    IOByteCount length)
{
	return kIOReturnUnsupported;
}

IOByteCount
IODTNVRAM::savePanicInfo(uint8_t *buffer, IOByteCount length)
{
	return 0;
}
