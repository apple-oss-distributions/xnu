/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _DOUBLEAGENT_TYPES_H_
#define _DOUBLEAGENT_TYPES_H_

#define DA_XATTR_MAXNAMELEN 127 // Must match the 'XATTR_MAXNAMELEN' in <sys/xattr.h>.
#define DA_XATTR_FINDERINFO_NAME "com.apple.FinderInfo" // Copy of XATTR_FINDERINFO_NAME in <sys/xattr.h>.
#define DA_XATTR_RESOURCEFORK_NAME "com.apple.ResourceFork" // Copy of DA_XATTR_RESOURCEFORK_NAME in <sys/xattr.h>.

#define MAX_NUM_OF_XATTRS 256
#define LISTXATTR_RESULT_MAX_NAMES_LEN (sizeof(DA_XATTR_RESOURCEFORK_NAME) + sizeof(DA_XATTR_FINDERINFO_NAME) + (MAX_NUM_OF_XATTRS * ((DA_XATTR_MAXNAMELEN + 1))))
#define LISTXATTR_RESULT_MAX_HINTS_LEN (MAX_NUM_OF_XATTRS * 2 * sizeof(uint32_t)) // hint = offset + length (per xattr).
#define LISTXATTR_RESULT_MAX_SIZE (LISTXATTR_RESULT_MAX_NAMES_LEN + LISTXATTR_RESULT_MAX_HINTS_LEN)

typedef char xattrname[DA_XATTR_MAXNAMELEN + 1];

typedef struct list_xattrs_result {
	/* header */
	uint64_t finderInfoOffset; // =0 if not present
	uint64_t resourceForkOffset; // =0 if not present
	uint64_t resourceForkLength; // Don't care if resourceForkOffset = 0
	uint64_t numOfXattrs;

	/* data:
	 * (1) names (separated with '\0')
	 * (2) ranges: offset + lengths (for caching)
	 * (dataLength = namesLength + rangesLength)
	 */
	uint64_t dataLength;
	uint64_t namesLength;
	uint64_t rangesLength;
	uint8_t  data[LISTXATTR_RESULT_MAX_SIZE];
} listxattrs_result_t;

#endif /* _DOUBLEAGENT_TYPES_H_ */
