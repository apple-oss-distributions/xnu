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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>

#include <darwintest.h>

static void
send_msg()
{
	int res = -1;
	uint64_t msg = malloc(0x2000);
	T_ASSERT_POSIX_SUCCESS(res = socket(AF_INET, SOCK_STREAM, 0), NULL);
	*(uint64_t*)(msg + 0x200) = 0;
	*(uint32_t*)(msg + 0x208) = 0;
	*(uint64_t*)(msg + 0x210) = msg;
	*(uint64_t*)msg = 0;
	*(uint64_t*)(msg + 8) = 0;
	*(uint64_t*)(msg + 0x218) = 1;
	*(uint64_t*)(msg + 0x220) = (msg + 0x40);
	*(uint64_t*)(msg + 0x40) = 0xa8;
	*(uint32_t*)(msg + 0x48) = 0x3a;
	*(uint32_t*)(msg + 0x4c) = 0x10000;
	memcpy((void*)(msg + 0x50), "\x7a\x3d\xc9\x5d\x24\x0e\xa5\xb4\xa9\xf2\xa5\x27\xc1\xf2\xbb\x18\x45\xca\x31\xbc\x12\x5c\x10\x55\xa0\x1b\x20\xb2\xfa\xe1\x88\x91\x9f\xee\x2c\x37\xd0\x97\x66\xba\x10\x36\xb2\x21\xf0\x42\xff\xbb\x36\x6c\x26\xc0\x70\x57\xc1\xaa\xc7\xb1\x39\x6c\xb5\xfb\xa0\x60\x57\xf0\xcd\xcd\x58\x89\x9a\xbf\x00\xd8\xa8\x47\xb9\x86\x6f\xa2\xa5\xa0\x56\x4c\x23\xe8\xbf\x3b\x2d\x9e\xdb\xe8\xec\x83\x2c\xbe\x52\x09\xad\x54\xb6\x65\xf4\x47\x58\x60\x9e\x31\x7c\xb0\x9b\xab\xc9\x1f\xd0\x1a\x65\x68\xad\x30\x57\x5e\x0b\x15\xc3\x40\x81\x32\x3f\xdd\xb2\xbd\x28\xd1\x2b\x16\xc0\xee\xdb\x58\x96\x77\x0c\x56\x9d\xc4", 146);
	*(uint64_t*)(msg + 0xe8) = 0xf0;
	*(uint32_t*)(msg + 0xf0) = 0xffff;
	*(uint32_t*)(msg + 0xf4) = 0x80000001;
	memcpy((void*)(msg + 0xf8), "\xfa\x84\xcc\x46\xe8\x4b\xfa\xf2\xfa\x5b\x17\x75\x79\x5b\x8a\x32\x2f\x9a\xd5\xdb\x5e\x3f\x09\xdd\x44\x4c\x94\x33\x08\xbe\x69\xb0\xec\x16\x56\x6f\xdb\xcb\x09\xd2\x6b\x13\x1d\xa9\xfd\x13\x13\x0f\x61\x6b\x82\x0a\x17\x4c\x38\x66\x86\x18\xcf\x81\xd5\xff\x8a\x90\xf3\x6d\x51\xb8\xab\x24\xd3\xe5\xcb\x57\xda\x13\x4c\x10\x99\xe1\x97\xcc\xc3\x0d\x10\x4d\xc3\x9a\xd6\x02\xef\x2a\xf6\x98\x0d\xff\xf1\x46\xd8\xc8\xdb\x80\x38\x81\xf9\xf4\x21\x4b\xd4\x32\xb0\x69\x44\x3b\x9e\x2b\x76\x40\x12\xc8\xce\xc2\x18\x05\x73\x47\xac\xaa\xac\x68\xb7\x6d\xb8\xe4\x67\xd6\x19\x66\x35\x8d\x34\xd6\x5d\xde\x0d\xdd\x3c\xee\xc9\x8f\x79\xaf\x57\x94\xd5\xe3\x25\x70\x16\x41\xbe\x2f\xe0\x9b\x84\x2d\xdf\x7a\x8b\x5f\xab\xba\x94\x8d\xf5\x01\xe2\x60\xd3\x50\x0f\xda\x55\xe2\x73\x97\xd4\xfb\x7e\xa4\x99\xf7\x9c\x40\x4d\x7e\xf2\x53\x87\xa2\x66\x19\x12\x5e\xce\xbd\xfc\xee\x83\xba\xf7\x3f\xc5\x94\x67\xf9\x08\xbb\x28\x8e\x26\x3c\x51", 223);
	*(uint64_t*)(msg + 0x228) = 0x198;
	*(uint32_t*)(msg + 0x230) = 0;
	int err = sendmsg(res, msg + 0x200, 0x80);
#if TARGET_OS_IOS || TARGET_OS_OSX
	T_ASSERT_EQ(err, -1, NULL);
	T_ASSERT_EQ(errno, 47, NULL);
#endif
}

T_DECL(tcp_send_invalid_address, "TCP send with an invalid address")
{
	send_msg();
}
