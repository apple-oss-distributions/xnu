/*
 * Copyright (c) 2022-2024 Apple Inc. All rights reserved.
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

#include <sys/vnode.h>
extern "C" {
#include <vfs/vfs_exclave_fs.h>
}
#include <IOKit/IOPlatformExpert.h>

#define APFS_VOLUME_OBJECT "AppleAPFSVolume"
#define kAPFSVolGroupUUIDKey "VolGroupUUID"

extern "C"
int
vfs_exclave_fs_query_volume_group(const uuid_string_t vguuid_str, bool *exists)
{
#if XNU_TARGET_OS_OSX
	OSDictionary *target = NULL, *filter = NULL;
	OSString *string = NULL;
	IOService *service = NULL;
	int error = 0;
	uuid_t vguuid;

	*exists = false;

	// Verify input uuid is a valid uuid
	error = uuid_parse(vguuid_str, vguuid);
	if (error) {
		return EINVAL;
	}

	// Look for APFS volume object that has Volume Group that matches the one we're looking for
	target = IOService::serviceMatching(APFS_VOLUME_OBJECT);
	if (!target) {
		// No APFS volumes found?
		return ENXIO;
	}

	filter = OSDictionary::withCapacity(1);
	if (!filter) {
		error = ENOMEM;
		goto out;
	}

	string = OSString::withCStringNoCopy(vguuid_str);
	if (!string) {
		error = ENOMEM;
		goto out;
	}

	if (!filter->setObject(kAPFSVolGroupUUIDKey, string)) {
		error = ENXIO;
		goto out;
	}

	if (!target->setObject(gIOPropertyMatchKey, filter)) {
		error = ENXIO;
		goto out;
	}

	if ((service = IOService::copyMatchingService(target)) != NULL) {
		*exists = true;
	}

out:
	if (target) {
		target->release();
	}

	if (filter) {
		filter->release();
	}

	if (string) {
		string->release();
	}

	if (service) {
		service->release();
	}

	return error;
#else
#pragma unused(vguuid_str)
#pragma unused(exists)
	return ENOTSUP;
#endif
}
