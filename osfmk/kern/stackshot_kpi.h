/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#ifndef _STACKSHOT_KPI_H_
#define _STACKSHOT_KPI_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

__enum_decl(stackshot_device_lock_flags_t, uint8_t, {
	stackshot_device_after_first_unlock = 1,
});

__enum_decl(stackshot_passcode_status_t, uint8_t, {
	stackshot_passcode_unset   = 0,
	stackshot_passcode_set     = 1,
	stackshot_passcode_unknown = 2,
});

__enum_decl(stackshot_device_lock_state_t, uint8_t, {
	stackshot_lock_state_device_unlocked = 0, // at least one user in the group is unlocked.
	stackshot_lock_state_device_locked   = 1,// all users in the group are locked.
	stackshot_lock_state_unknown         = 2,
});

void stackshot_update_lock_state(stackshot_device_lock_state_t lock_state);
void stackshot_update_passcode_status(stackshot_passcode_status_t primary_user_status);

__END_DECLS

#endif /* _STACKSHOT_KPI_H_ */
