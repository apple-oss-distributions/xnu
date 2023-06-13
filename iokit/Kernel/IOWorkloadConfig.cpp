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

#define IOKIT_ENABLE_SHARED_PTR

#include <IOKit/IOLib.h>
#include <IOKit/IOReturn.h>

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/c++/OSSerialize.h>

#include <sys/work_interval.h>
#include <sys/param.h>

#include <kern/thread_group.h>
#include <kern/work_interval.h>
#include <kern/workload_config.h>

#if DEVELOPMENT || DEBUG
#define WLC_LOG(fmt, args...) IOLog("WorkloadConfig: " fmt, ##args)
#else
#define WLC_LOG(fmt, args...)
#endif

/* Limit criticality offsets.  */
#define MAX_CRITICALITY_OFFSET 16


/* Plist keys/values. */
#define kWorkloadIDTableKey   "WorkloadIDTable"
#define kRootKey              "Root"
#define kPhasesKey            "Phases"
#define kWorkIntervalTypeKey  "WorkIntervalType"
#define kWorkloadClassKey     "WorkloadClass"
#define kCriticalityOffsetKey "CriticalityOffset"
#define kDefaultPhaseKey      "DefaultPhase"
#define kFlagsKey             "Flags"
#define kWorkloadIDConfigurationFlagsKey "WorkloadIDConfigurationFlags"

#define kDisableWorkloadClassThreadPolicyValue "DisableWorkloadClassThreadPolicy"
#define kWIComplexityAllowedValue              "ComplexityAllowed"

#define ARRAY_LEN(x) (sizeof (x) / sizeof (x[0]))

#if !CONFIG_THREAD_GROUPS
#define THREAD_GROUP_FLAGS_EFFICIENT   0
#define THREAD_GROUP_FLAGS_APPLICATION 0
#define THREAD_GROUP_FLAGS_CRITICAL    0
#define THREAD_GROUP_FLAGS_BEST_EFFORT 0
#define THREAD_GROUP_FLAGS_ABSENT      0
#endif /* CONFIG_THREAD_GROUPS */

/* BEGIN IGNORE CODESTYLE */
static const struct WorkloadClassData {
	const char *name;
	UInt32 workIntervalFlags;
	UInt32 threadGroupFlags;
} wlClassData[] = {
	[WI_CLASS_NONE] =
	{
		.name = "NONE",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = THREAD_GROUP_FLAGS_ABSENT,
	},
	[WI_CLASS_DISCRETIONARY] =
	{
		.name = "DISCRETIONARY",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = THREAD_GROUP_FLAGS_EFFICIENT,
	},
	[WI_CLASS_BEST_EFFORT] =
	{
		.name = "BEST_EFFORT",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = THREAD_GROUP_FLAGS_BEST_EFFORT,
	},
	[WI_CLASS_APP_SUPPORT] =
	{
		.name = "APPLICATION_SUPPORT",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = 0,
	},
	[WI_CLASS_APPLICATION] =
	{
		.name = "APPLICATION",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = THREAD_GROUP_FLAGS_APPLICATION,
	},
	[WI_CLASS_SYSTEM] =
	{
		.name = "SYSTEM",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = 0,
	},
	[WI_CLASS_SYSTEM_CRITICAL] =
	{
		.name = "SYSTEM_CRITICAL",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID,
		.threadGroupFlags = THREAD_GROUP_FLAGS_CRITICAL,
	},
	[WI_CLASS_REALTIME] =
	{
		.name = "REALTIME",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID |
		                     WORK_INTERVAL_WORKLOAD_ID_RT_ALLOWED,
		.threadGroupFlags = 0,
	},
	[WI_CLASS_REALTIME_CRITICAL] =
	{
		.name = "REALTIME_CRITICAL",
		.workIntervalFlags = WORK_INTERVAL_WORKLOAD_ID_HAS_ID |
		                     WORK_INTERVAL_WORKLOAD_ID_RT_ALLOWED |
		                     WORK_INTERVAL_WORKLOAD_ID_RT_CRITICAL,
		.threadGroupFlags = THREAD_GROUP_FLAGS_CRITICAL,
	},
};
/* END IGNORE CODESTYLE */

struct FlagMap {
	const char *str;
	UInt32 flags;
};

static inline IOReturn
stringToFlags(const OSString &str, UInt32 &flags, const struct FlagMap *map,
    size_t mapLen)
{
	for (size_t i = 0; i < mapLen; i++) {
		if (str.isEqualTo(map[i].str)) {
			flags = map[i].flags;
			return kIOReturnSuccess;
		}
	}

	return kIOReturnNotFound;
}

static inline IOReturn
flagsToString(const UInt32 flags, OSSharedPtr<OSString> &str, const struct FlagMap *map,
    size_t mapLen)
{
	for (size_t i = 0; i < mapLen; i++) {
		if (flags == map[i].flags) {
			str = OSString::withCStringNoCopy(map[i].str);
			return kIOReturnSuccess;
		}
	}

	return kIOReturnNotFound;
}

/* BEGIN IGNORE CODESTYLE */
static const struct FlagMap typeMap[] = {
	{
		.str = "DEFAULT",
		.flags = WORK_INTERVAL_TYPE_DEFAULT |
		         WORK_INTERVAL_FLAG_UNRESTRICTED,
	},
	{
		.str = "COREAUDIO",
		.flags = WORK_INTERVAL_TYPE_COREAUDIO |
		         WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN |
		         WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH,
	},
	{
		.str = "COREANIMATION",
		.flags = WORK_INTERVAL_TYPE_COREANIMATION,
	},
	{
		.str = "CA_RENDER_SERVER",
		.flags = WORK_INTERVAL_TYPE_CA_RENDER_SERVER,
	},
	{
		.str = "FRAME_COMPOSITOR",
		.flags = WORK_INTERVAL_TYPE_FRAME_COMPOSITOR,
	},
	{
		.str = "CA_CLIENT",
		.flags = WORK_INTERVAL_TYPE_CA_CLIENT |
		         WORK_INTERVAL_FLAG_UNRESTRICTED,
	},
	{
		.str = "HID_DELIVERY",
		.flags = WORK_INTERVAL_TYPE_HID_DELIVERY,
	},
	{
		.str = "COREMEDIA",
		.flags = WORK_INTERVAL_TYPE_COREMEDIA,
	},
	{
		.str = "ARKIT",
		.flags = WORK_INTERVAL_TYPE_ARKIT |
		         WORK_INTERVAL_FLAG_FINISH_AT_DEADLINE,
	},
	{
		.str  = "AUDIO_CLIENT",
		.flags = WORK_INTERVAL_TYPE_COREAUDIO |
		         WORK_INTERVAL_FLAG_UNRESTRICTED |
		         WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN |
		         WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH
	},
};
/* END IGNORE CODESTYLE */

static IOReturn
unparseWorkIntervalType(const UInt32 createFlags, OSSharedPtr<OSString> &typeStr)
{
	IOReturn ret = flagsToString(createFlags, typeStr, typeMap,
	    ARRAY_LEN(typeMap));
	if (ret != kIOReturnSuccess) {
		WLC_LOG("unrecognised create flags: 0x%x\n", createFlags);
	}

	return ret;
}

static IOReturn
parseWorkIntervalType(const OSSymbol &id, const OSObject *typeObj, UInt32 &createFlags)
{
	OSSharedPtr<OSString> defaultIntervalType = OSString::withCString("DEFAULT");

	const OSString *typeStr = OSDynamicCast(OSString, typeObj);
	if (typeStr == nullptr) {
		typeStr = defaultIntervalType.get();
	}

	IOReturn ret = stringToFlags(*typeStr, createFlags, typeMap,
	    ARRAY_LEN(typeMap));
	if (ret != kIOReturnSuccess) {
		WLC_LOG("unrecognised \"" kWorkIntervalTypeKey "\": \"%s\"\n",
		    typeStr->getCStringNoCopy());
	}

	return ret;
}

static IOReturn
parseWorkloadClass(const OSSymbol &id, const OSObject *wlClassObj, wi_class_t &wiClass)
{
	const OSString *wlClass = OSDynamicCast(OSString, wlClassObj);
	if (wlClass == nullptr) {
		wiClass = WI_CLASS_NONE;
		return kIOReturnSuccess;
	}

	for (size_t i = 0; i < ARRAY_LEN(wlClassData); i++) {
		if (wlClassData[i].name != nullptr &&
		    wlClass->isEqualTo(wlClassData[i].name)) {
			wiClass = (wi_class_t)i;
			return kIOReturnSuccess;
		}
	}

	WLC_LOG("%s: unknown %s: \"%s\"\n", id.getCStringNoCopy(),
	    kWorkloadClassKey, wlClass->getCStringNoCopy());
	return kIOReturnError;
}

static IOReturn
parseCriticalityOffset(const OSSymbol &id, const wi_class_t wiClass,
    const OSObject *cOffsetObj, uint8_t &criticalityOffset)
{
	if (wiClass != WI_CLASS_SYSTEM_CRITICAL &&
	    wiClass != WI_CLASS_REALTIME_CRITICAL &&
	    wiClass != WI_CLASS_BEST_EFFORT &&
	    wiClass != WI_CLASS_APP_SUPPORT &&
	    wiClass != WI_CLASS_SYSTEM) {
		criticalityOffset = 0;
		return kIOReturnSuccess;
	}

	const OSNumber *cOffset = OSDynamicCast(OSNumber, cOffsetObj);
	if (cOffset == nullptr) {
		criticalityOffset = 0;
		return kIOReturnSuccess;
	}

	UInt64 criticalityOffset64 = cOffset->unsigned64BitValue();
	const int nBytes = cOffset->numberOfBytes();
	if (nBytes <= sizeof(criticalityOffset64) &&
	    criticalityOffset64 < MAX_CRITICALITY_OFFSET) {
		criticalityOffset = (uint8_t)criticalityOffset64;
		return kIOReturnSuccess;
	}

	WLC_LOG("%s: criticality offset too large\n", id.getCStringNoCopy());
	return kIOReturnError;
}

static IOReturn
parseFlags(const OSSymbol &id, const OSObject *flagsObj, UInt32 &threadGroupFlags,
    UInt32 &workIntervalFlags)
{
	/* Optional, so just carry on if not found. */
	if (flagsObj == nullptr) {
		return kIOReturnSuccess;
	}

	OSArray *flags = OSDynamicCast(OSArray, flagsObj);
	if (flags == nullptr) {
		WLC_LOG("failed to parse \"" kFlagsKey "\"\n");
		return kIOReturnError;
	}

	/* BEGIN IGNORE CODESTYLE */
	__block IOReturn ret = kIOReturnSuccess;
	flags->iterateObjects(^bool (OSObject *object) {
		const OSString *flag = OSDynamicCast(OSString, object);
		if (flag == nullptr) {
			WLC_LOG("%s: non-string flag found\n", id.getCStringNoCopy());
			ret = kIOReturnError;
			return true;

		}

		/* Ignore unknown flags. */
		if (flag->isEqualTo(kWIComplexityAllowedValue)) {
			workIntervalFlags |= WORK_INTERVAL_WORKLOAD_ID_COMPLEXITY_ALLOWED;
		}

		return false;
	});
	/* END IGNORE CODESTYLE */

	return ret;
}

static
IOReturn
parsePhases(workload_config_ctx_t *ctx, const OSSymbol &id, OSObject *phasesObj)
{
	__block IOReturn ret = kIOReturnError;

	OSDictionary *phases = OSDynamicCast(OSDictionary, phasesObj);
	if (phases == nullptr) {
		WLC_LOG("%s: failed to find dictionary for \"" kPhasesKey "\"\n",
		    id.getCStringNoCopy());
		return kIOReturnError;
	}

	/* There should be at least one phase described. */
	ret = kIOReturnError;

	/* BEGIN IGNORE CODESTYLE */
	phases->iterateObjects(^bool (const OSSymbol *phase, OSObject *value) {
		const OSDictionary *dict = OSDynamicCast(OSDictionary, value);
		if (dict == nullptr) {
			WLC_LOG("%s: failed to find dictionary for \"%s\" phase\n",
			    id.getCStringNoCopy(), phase->getCStringNoCopy());
			ret = kIOReturnError;
			return true;
		}

		UInt32 createFlags = 0;
		ret = parseWorkIntervalType(id, dict->getObject(kWorkIntervalTypeKey),
		    createFlags);
		if (ret != kIOReturnSuccess) {
			return true;
		}

		wi_class_t wiClass = WI_CLASS_NONE;
		ret = parseWorkloadClass(id, dict->getObject(kWorkloadClassKey), wiClass);
		if (ret != kIOReturnSuccess) {
			return true;
		}
		const struct WorkloadClassData classData = wlClassData[wiClass];

		uint8_t criticalityOffset = 0;
		ret = parseCriticalityOffset(id, wiClass,
		    dict->getObject(kCriticalityOffsetKey), criticalityOffset);
		if (ret != kIOReturnSuccess) {
			return true;
		}

		UInt32 threadGroupFlags = classData.threadGroupFlags;
		UInt32 workIntervalFlags = classData.workIntervalFlags;
		ret = parseFlags(id, dict->getObject(kFlagsKey), threadGroupFlags, workIntervalFlags);
		if (ret != kIOReturnSuccess) {
			return true;
		}

		const workload_config_t config = {
		    .wc_thread_group_flags = threadGroupFlags,
		    .wc_flags = workIntervalFlags,
		    .wc_create_flags = createFlags,
		    .wc_class_offset = (uint8_t)criticalityOffset,
		    .wc_class = wiClass,
		};
		ret = workload_config_insert(ctx, id.getCStringNoCopy(), phase->getCStringNoCopy(), &config);
		if (ret != kIOReturnSuccess) {
			WLC_LOG("%s: failed to add \"%s\" phase\n",
			id.getCStringNoCopy(), phase->getCStringNoCopy());
			return true;
		}

		return false;
	});
	/* END IGNORE CODESTYLE */

	return ret;
}

static IOReturn
parseRoot(const OSSymbol &id, const OSObject *rootDict, OSString *&defaultPhase)
{
	const OSDictionary *root = OSDynamicCast(OSDictionary, rootDict);
	if (root == nullptr) {
		WLC_LOG("%s: failed to find dictionary for \"" kRootKey "\"\n",
		    id.getCStringNoCopy());
		return kIOReturnError;
	}

	defaultPhase = OSDynamicCast(OSString, root->getObject(kDefaultPhaseKey));
	if (defaultPhase == nullptr) {
		WLC_LOG("%s: failed to find \"" kDefaultPhaseKey"\" in \"" kRootKey "\" dictionary\n",
		    id.getCStringNoCopy());
		return kIOReturnError;
	}

	if (defaultPhase->getLength() == 0) {
		WLC_LOG("%s: \"" kDefaultPhaseKey" \" is empty in \"" kRootKey "\" dictionary\n",
		    id.getCStringNoCopy());
		return kIOReturnError;
	}

	return kIOReturnSuccess;
}

static IOReturn
parseWorkloadIDTable(workload_config_ctx_t *ctx, OSDictionary *IDTable)
{
	/*
	 * At least one valid entry is expected, so start off with error to
	 * catch an empty table or one with no valid entries.
	 */
	__block IOReturn ret = kIOReturnError;

	/* BEGIN IGNORE CODESTYLE */
	IDTable->iterateObjects(^bool (const OSSymbol *id, OSObject *value) {
		/* Validate the workload ID. */
		if (id->getLength() == 0) {
			WLC_LOG("zero length ID in \"" kWorkloadIDTableKey "\"\n");
			ret = kIOReturnError;
			return true;
		}

		/* Parse its properties. */
		OSDictionary *idConfig = OSDynamicCast(OSDictionary, value);
		if (idConfig == nullptr) {
			WLC_LOG("failed to find dictionary for \"%s\"\n",
			id->getCStringNoCopy());
			ret = kIOReturnError;
			return true;
		}

		ret = parsePhases(ctx, *id, idConfig->getObject(kPhasesKey));
		if (ret != kIOReturnSuccess) {
			return true;
		}

		OSString *defaultPhase = nullptr;
		ret = parseRoot(*id, idConfig->getObject(kRootKey), defaultPhase);
		if (ret != kIOReturnSuccess) {
			return true;
		}

		/* Fails if the specified phase doesn't exist.. */
		ret = workload_config_set_default(ctx, id->getCStringNoCopy(),
		defaultPhase->getCStringNoCopy());
		if (ret != kIOReturnSuccess) {
			WLC_LOG("failed to set default phase (%s) for \"%s\"\n",
			defaultPhase->getCStringNoCopy(), id->getCStringNoCopy());
			return true;
		}

		return false;
	});
	/* END IGNORE CODESTYLE */

	return ret;
}

static IOReturn
parseWorkloadIDConfigurationFlags(workload_config_ctx_t *ctx, const OSObject *idTableFlagsObj)
{
	/* Optional, so just carry on if not found. */
	if (idTableFlagsObj == nullptr) {
		return kIOReturnSuccess;
	}

	OSArray *idTableFlags = OSDynamicCast(OSArray, idTableFlagsObj);
	if (idTableFlags == nullptr) {
		WLC_LOG("failed to parse \""
		    kWorkloadIDConfigurationFlagsKey "\"\n");
		return kIOReturnError;
	}

	/* BEGIN IGNORE CODESTYLE */
	__block IOReturn ret = kIOReturnSuccess;
	idTableFlags->iterateObjects(^bool (OSObject *object) {
		const OSString *flag = OSDynamicCast(OSString, object);
		if (flag == nullptr) {
			WLC_LOG("non-string Workload ID Table flag found\n");
			ret = kIOReturnError;
			return true;
		}

		if (flag->isEqualTo(kDisableWorkloadClassThreadPolicyValue)) {
			workload_config_clear_flag(ctx, WLC_F_THREAD_POLICY);
		}

		return false;
	});
	/* END IGNORE CODESTYLE */

	return ret;
}

static IOReturn
unparseWorkloadIDConfigurationFlags(OSSharedPtr<OSDictionary> &plist)
{
	workload_config_flags_t flags = WLC_F_NONE;

	/* There may be no config at all. That's ok. */
	if (workload_config_get_flags(&flags) != KERN_SUCCESS) {
		return kIOReturnSuccess;
	}

	/* Workload config can change thread policy scheduling - the default. */
	if ((flags & WLC_F_THREAD_POLICY) != 0) {
		return kIOReturnSuccess;
	}

	OSSharedPtr<OSArray> idTableFlags = OSArray::withCapacity(1);
	OSSharedPtr<OSString> flag = OSString::withCString(kDisableWorkloadClassThreadPolicyValue);
	if (!idTableFlags->setObject(flag) ||
	    !plist->setObject(kWorkloadIDConfigurationFlagsKey, idTableFlags)) {
		return kIOReturnError;
	}

	return kIOReturnSuccess;
}

extern "C" {
extern IOReturn IOParseWorkloadConfig(workload_config_ctx_t *, const char *, size_t);
extern IOReturn IOUnparseWorkloadConfig(char *, size_t *);
}

/* Called locked. */
IOReturn
IOParseWorkloadConfig(workload_config_ctx_t *ctx, const char *buffer, size_t size)
{
	IOReturn ret = kIOReturnError;

	OSSharedPtr<OSString> unserializeErrorString = nullptr;
	OSSharedPtr<OSObject> obj = nullptr;
	OSDictionary *idTable = nullptr;
	OSDictionary *dict = nullptr;

	ret = workload_config_init(ctx);
	if (ret != kIOReturnSuccess) {
		WLC_LOG("failed to initialize workload configuration\n");
		goto out;
	}

	obj = OSUnserializeXML(buffer, unserializeErrorString);
	dict = OSDynamicCast(OSDictionary, obj.get());
	if (dict == nullptr) {
		WLC_LOG("failed to unserialize plist\n");
		ret = kIOReturnError;
		goto out;
	}

	idTable = OSDynamicCast(OSDictionary, dict->getObject(kWorkloadIDTableKey));
	if (idTable == nullptr) {
		WLC_LOG("failed to find " kWorkloadIDTableKey "\n");
		ret = kIOReturnError;
		goto out;
	}

	ret = parseWorkloadIDTable(ctx, idTable);
	if (ret != kIOReturnSuccess) {
		goto out;
	}

	ret = parseWorkloadIDConfigurationFlags(ctx, dict->getObject(kWorkloadIDConfigurationFlagsKey));
	if (ret != kIOReturnSuccess) {
		goto out;
	}

	ret = kIOReturnSuccess;

out:
	if (ret != kIOReturnSuccess) {
		workload_config_free(ctx);
	}

	return ret;
}

/*
 * Does the reverse of IOParseWorkloadConfig() - i.e. serializes the internal
 * workload configuration.
 * The serialized workload config is copied to 'buffer' (if non-NULL).
 * size is in/out - it describes the size of buffer and on return the length of
 * the serialized config.
 */
IOReturn
IOUnparseWorkloadConfig(char *buffer, size_t *size)
{
	assert(size != nullptr);

	OSSharedPtr<OSDictionary> dict = nullptr;;
	OSSharedPtr<OSDictionary> idTable = nullptr;
	OSSharedPtr<OSSerialize> serialize = nullptr;

	serialize = OSSerialize::withCapacity(1);
	if (serialize == nullptr) {
		return kIOReturnNoMemory;
	}

	dict = OSDictionary::withCapacity(1);
	if (dict == nullptr) {
		return kIOReturnNoMemory;
	}

	idTable = OSDictionary::withCapacity(1);
	if (idTable == nullptr) {
		return kIOReturnNoMemory;
	}

	__block IOReturn ret = kIOReturnSuccess;
	/* BEGIN IGNORE CODESTYLE */
	workload_config_iterate(^(const char *id_str, const void *config) {
		OSSharedPtr<OSDictionary> idDict = OSDictionary::withCapacity(1);
		if (idDict == nullptr) {
			ret = kIOReturnNoMemory;
			return true;
		}

		OSSharedPtr<OSDictionary> phase = OSDictionary::withCapacity(1);
		if (phase == nullptr) {
			ret = kIOReturnNoMemory;
			return true;
		}

		workload_config_phases_iterate(config, ^(const char *phase_str,
		    const bool is_default, const workload_config_t *wc) {
			OSSharedPtr<OSDictionary> phaseData = OSDictionary::withCapacity(1);
			if (phaseData == nullptr) {
				ret = kIOReturnNoMemory;
				return true;
			}

			if (wc->wc_class != WI_CLASS_NONE) {
				assert3u(wc->wc_class, <, WI_CLASS_COUNT);
				OSSharedPtr<OSString> wClass = OSString::withCString(wlClassData[wc->wc_class].name);
				if (wClass == nullptr || !phaseData->setObject(kWorkloadClassKey, wClass)) {
					ret = kIOReturnError;
					return true;
				}
			}

			if (wc->wc_class_offset > 0) {
				OSSharedPtr<OSNumber> criticalityOffset = OSNumber::withNumber(wc->wc_class_offset, 8);
				if (criticalityOffset == nullptr ||
				    !phaseData->setObject(kCriticalityOffsetKey, criticalityOffset)) {
					ret = kIOReturnError;
					return true;
				}
			}

			OSSharedPtr<OSString> type = nullptr;
			if (unparseWorkIntervalType(wc->wc_create_flags, type) != kIOReturnSuccess ||
			    !phaseData->setObject(kWorkIntervalTypeKey, type)) {
				ret = kIOReturnError;
				return true;
			}


			OSSharedPtr<OSArray> flags = OSArray::withCapacity(2);
			if (flags == nullptr) {
				ret = kIOReturnError;
				return true;
			}
			if ((wc->wc_flags & WORK_INTERVAL_WORKLOAD_ID_COMPLEXITY_ALLOWED) != 0) {
				OSSharedPtr<OSString> WIComplexityAllowedStr =
				    OSString::withCString(kWIComplexityAllowedValue);
				if (WIComplexityAllowedStr == nullptr || !flags->setObject(WIComplexityAllowedStr)) {
					ret = kIOReturnError;
					return true;
				}
			}
			if (flags->getCount() && !phaseData->setObject(kFlagsKey, flags)) {
				ret = kIOReturnError;
				return true;
			}

			if (!phase->setObject(phase_str, phaseData)) {
				ret = kIOReturnError;
				return true;
			}

			if (is_default) {
				OSSharedPtr<OSDictionary> root = OSDictionary::withCapacity(1);
				OSSharedPtr<OSString> phaseStr = OSString::withCString(phase_str);

				if (root == nullptr || phaseStr == nullptr ||
				    !root->setObject(kDefaultPhaseKey, phaseStr)) {
					ret = kIOReturnError;
					return true;
				}

				if (!idDict->setObject(kRootKey, root)) {
					ret = kIOReturnError;
					return true;
				}
			}

			return false;

		});

		if (ret != kIOReturnSuccess) {
			return true;
		}

		if (!idDict->setObject(kPhasesKey, phase)) {
			ret = kIOReturnError;
			return true;
		}

		if (!idTable->setObject(id_str, idDict)) {
			ret = kIOReturnError;
			return true;
		}

		return false;
	});
	/* END IGNORE CODESTYLE */

	if (ret != kIOReturnSuccess) {
		return ret;
	}

	OSSharedPtr<OSDictionary> plist = OSDictionary::withCapacity(1);
	if (plist == nullptr) {
		return kIOReturnError;
	}

	if (idTable->getCount() > 0 &&
	    !plist->setObject(kWorkloadIDTableKey, idTable)) {
		return kIOReturnError;
	}

	if (unparseWorkloadIDConfigurationFlags(plist) != kIOReturnSuccess) {
		return kIOReturnError;
	}

	if (!plist->serialize(serialize.get())) {
		return kIOReturnError;
	}

	if (buffer != nullptr) {
		(void) strlcpy(buffer, serialize->text(), *size);
	}
	*size = serialize->getLength();

	return kIOReturnSuccess;
}
