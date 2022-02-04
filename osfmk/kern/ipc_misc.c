/*
 * Copyright (c) 2008, 2010 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/notify.h>
#include <ipc/ipc_port.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_misc.h>

#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

extern void fileport_releasefg(struct fileglob *);

/*
 * fileport_alloc
 *
 * Description: Obtain a send right for the given fileglob, which must be
 *		referenced.
 *
 * Parameters:  fg		A fileglob.
 *
 * Returns:     Port of type IKOT_FILEPORT with fileglob set as its kobject.
 *              Port is returned with a send right.
 */
ipc_port_t
fileport_alloc(struct fileglob *fg)
{
	return ipc_kobject_alloc_port((ipc_kobject_t)fg, IKOT_FILEPORT,
	           IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);
}


/*
 * fileport_get_fileglob
 *
 * Description: Obtain the fileglob associated with a given port.
 *
 * Parameters: port		A Mach port of type IKOT_FILEPORT.
 *
 * Returns:    NULL		The given Mach port did not reference a
 *				fileglob.
 *	       !NULL		The fileglob that is associated with the
 *				Mach port.
 *
 * Notes: The caller must have a reference on the fileport.
 */
struct fileglob *
fileport_port_to_fileglob(ipc_port_t port)
{
	if (IP_VALID(port)) {
		return ipc_kobject_get_stable(port, IKOT_FILEPORT);
	}
	return NULL;
}


/*
 * fileport_no_senders
 *
 * Description: Handle a no-senders notification for a fileport.  Unless
 *              the message is spoofed, destroys the port and releases
 *              its reference on the fileglob.
 *
 * Parameters: msg		A Mach no-senders notification message.
 */
static void
fileport_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	struct fileglob *fg;

	fg = ipc_kobject_dealloc_port(port, mscount, IKOT_FILEPORT);

	fileport_releasefg(fg);
}

IPC_KOBJECT_DEFINE(IKOT_FILEPORT,
    .iko_op_stable     = true,
    .iko_op_no_senders = fileport_no_senders);

/*
 * fileport_invoke
 *
 * Description: Invoke a function with the fileglob underlying the fileport.
 *		Returns the error code related to the fileglob lookup.
 *
 * Parameters:	task		The target task
 *		action		The function to invoke with the fileglob
 *		arg		Anonymous pointer to caller state
 *		rval		The value returned from calling 'action'
 */
kern_return_t
fileport_invoke(task_t task, mach_port_name_t name,
    int (*action)(mach_port_name_t, struct fileglob *, void *),
    void *arg, int *rval)
{
	kern_return_t kr;
	ipc_port_t fileport;
	struct fileglob *fg;

	kr = ipc_object_copyin(task->itk_space, name,
	    MACH_MSG_TYPE_COPY_SEND, (ipc_object_t *)&fileport, 0, NULL,
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if ((fg = fileport_port_to_fileglob(fileport)) != NULL) {
		*rval = (*action)(name, fg, arg);
	} else {
		kr = KERN_FAILURE;
	}
	ipc_port_release_send(fileport);
	return kr;
}

/*
 * fileport_walk
 *
 * Description: Invoke the action function on every fileport in the task.
 *
 * Parameters:  task		The target task
 *		countp		Returns how many ports were found
 *		action		The function to invoke on each fileport
 */
kern_return_t
fileport_walk(task_t task, size_t *countp,
    bool (^cb)(size_t i, mach_port_name_t, struct fileglob *))
{
	ipc_space_t space = task->itk_space;
	ipc_entry_t table;
	ipc_entry_num_t tsize;
	size_t count = 0;

	is_read_lock(space);
	if (!is_active(space)) {
		is_read_unlock(space);
		return KERN_INVALID_TASK;
	}

	table = is_active_table(space);
	tsize = table->ie_size;

	for (mach_msg_type_number_t index = 1; index < tsize; index++) {
		ipc_entry_bits_t bits = table[index].ie_bits;
		ipc_object_t io = table[index].ie_object;
		mach_port_name_t name;
		struct fileglob *fg;

		if (IE_BITS_TYPE(bits) & MACH_PORT_TYPE_SEND) {
			name = MACH_PORT_MAKE(index, IE_BITS_GEN(bits));
			fg   = fileport_port_to_fileglob(ip_object_to_port(io));

			if (fg == NULL) {
				continue;
			}
			if (cb && !cb(count, name, fg)) {
				cb = NULL;
				if (countp == NULL) {
					break;
				}
			}
			count++;
		}
	}

	is_read_unlock(space);

	if (countp) {
		*countp = count;
	}

	return KERN_SUCCESS;
}
