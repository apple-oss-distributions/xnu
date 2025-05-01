/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <IOKit/IOProviderPropertyMerger.h>
#include <IOKit/IOService.h>

#define super IOService
OSDefineMetaClassAndStructors(IOProviderPropertyMerger, IOService);

bool
IOProviderPropertyMerger::init(OSDictionary * dictionary)
{
	OSDictionary *mergeProperties = OSDynamicCast(OSDictionary, dictionary->getObject(kIOProviderMergePropertiesKey));
	OSDictionary *parentMergeProperties = OSDynamicCast(OSDictionary, dictionary->getObject(kIOProviderParentMergePropertiesKey));

	// remove security-sensitive properties from the dictionary used to merge properties to provider
	if (mergeProperties) {
		mergeProperties->removeObject(gIOServiceDEXTEntitlementsKey);
	}
	if (parentMergeProperties) {
		parentMergeProperties->removeObject(gIOServiceDEXTEntitlementsKey);
	}

	return super::init(dictionary);
}

bool
IOProviderPropertyMerger::setProperty(const OSSymbol * aKey, OSObject * anObject)
{
	// Disallow modifying security-sensitive properties
	if (aKey->isEqualTo(kIOProviderMergePropertiesKey) || aKey->isEqualTo(kIOProviderParentMergePropertiesKey)) {
		return false;
	}
	return super::setProperty(aKey, anObject);
}

void
IOProviderPropertyMerger::setPropertyTable(OSDictionary * dict __unused)
{
	// Disallow changing the entire property table since that can change security-sensitive properties
}
