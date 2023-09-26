/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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

#ifndef _IOKIT_IOEXTENSIBLEPANICLOG_H
#define _IOKIT_IOEXTENSIBLEPANICLOG_H

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSPtr.h>
#include <IOKit/IOLib.h>
#include <DriverKit/IOExtensiblePaniclog.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

__BEGIN_DECLS
#include <kern/ext_paniclog.h>
__END_DECLS

class IOExtensiblePaniclog : public OSObject
{
	OSDeclareDefaultStructorsWithDispatch(IOExtensiblePaniclog);

private:
	ext_paniclog_handle_t *extPaniclogHandle;

	IOBufferMemoryDescriptor *iomd;

protected:
	bool init() APPLE_KEXT_OVERRIDE;

	void free(void) APPLE_KEXT_OVERRIDE;

public:

	/*!
	 * @brief       This function is to be called to create IOExtensiblePaniclog object.
	 * @discussion  First function to be called.
	 *
	 * @param       uuid  The UUID of the handle.
	 * @param       data_id The pointer to a string describing the handle. MAX length of 32.
	 * @param       max_len The maximum length of the buffer.
	 * @param       options Options to be passed while creating the handle
	 * @param       out The pointer to the created IOExtensiblePaniclog object. NULL in case of an error.
	 * @return      True in case of success. False in case of an error.
	 */
	static bool createWithUUID(uuid_t uuid, const char *data_id,
	    uint32_t max_len, ext_paniclog_create_options_t options, IOExtensiblePaniclog **out);

	/*!
	 * @brief       This function is called to set the IOExtensiblePaniclog object active.
	 * @discussion  When it is set active, it is picked up and added to the extensible paniclog
	 *              in case of a panic.
	 *
	 * @return      0 on success, negative value in case of failure.
	 */
	int setActive();

	/*!
	 * @brief       This function is called to set the IOExtensiblePaniclog object inactive.
	 * @discussion  When it is set inactive, this buffer is not picked up in case of a panic
	 *
	 * @return      True in case of success. False in case of an error.
	 */
	int setInactive();

	/*!
	 * @brief       This function is called to insert data into the buffer.
	 * @discussion  This function overwrites the data in the buffer. The write starts from
	 *              offset 0 and continues until 'len'
	 *
	 * @param       addr The address of the source buffer
	 * @param       len The length to be copied.
	 *
	 * @return      0 in case of success. Negative in case of an error.
	 */
	int insertData(void *addr, uint32_t len);

	/*!
	 * @brief       This function is called to insert data into the buffer.
	 * @discussion  This function overwrites the data in the buffer. The write starts from
	 *              last written byte and continues until 'len'
	 *
	 * @param       addr The address of the source buffer
	 * @param       len The length to be copied.
	 *
	 * @return      0 in case of success. Negative in case of an error.
	 */
	int appendData(void *addr, uint32_t len);

	/*!
	 * @brief       This function is called to get a pointer to the ext paniclog buffer
	 * @discussion  After this function is called, the user is responsible for copying data into the buffer.
	 *              The entire buffer is copied when a system panics.
	 *              After claiming the buffer, yieldBuffer() has to be called to set the used_len of the buffer
	 *              before calling insertData() or appendData()
	 *
	 * @return      Returns the address of the buffer.
	 */
	void *claimBuffer();

	/*!
	 * @brief       This function is called to yield the buffer and set the used_len for the buffer
	 * @discussion  After this function call, insertData() and appendData() can be called.
	 *
	 * @param       used_len The length of the buffer used by the client.
	 *
	 * @return      0 in case of success. Negative in case of an error.
	 */
	int yieldBuffer(uint32_t used_len);

	/*!
	 * @brief       This function is called to set the used len of the buffer
	 *
	 * @param       used_len The length of the buffer used by the client.
	 *
	 * @return      0 in case of success. Negative in case of an error.
	 */
	int setUsedLen(uint32_t used_len);
};

#endif // _IOKIT_IOEXTENSIBLEPANICLOG_H
