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

#include "mocks/std_safe.h"
#include "mocks/dt_proxy.h"
#include "fibers/fibers.h"
#include "mock_thread.h"
#include "unit_test_utils.h"

#include <vm/vm_map_xnu.h>

static void
may_yield(fiber_yield_reason_t reason)
{
	if (ut_mocks_use_fibers) {
		fibers_may_yield_internal_with_reason(reason);
	}
}

T_MOCK_F(kern_return_t,
vm_entry_lock_shared, (
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how),
(map, map_held, entry, addr, how))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);

	kern_return_t result = vm_entry_lock_shared(map, map_held, entry, addr, how);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_LOCK);

	return result;
}

T_MOCK_F(void,
vm_entry_unlock_shared,
(vm_map_t map __unused,
vm_map_entry_t entry),
(map, entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);

	vm_entry_unlock_shared(map, entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

T_MOCK_F(kern_return_t,
vm_entry_lock_exclusive, (
	vm_map_t                map,
	lck_rw_type_t           map_held,
	vm_map_entry_t          entry,
	vm_map_address_t        addr,
	wait_interrupt_t        how), (
	map,
	map_held,
	entry,
	addr,
	how))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);

	kern_return_t result = vm_entry_lock_exclusive(map, map_held, entry, addr, how);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_LOCK);

	return result;
}

T_MOCK_F(void,
vm_entry_unlock_exclusive,
(vm_map_t map,
vm_map_entry_t entry),
(map, entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);

	vm_entry_unlock_exclusive(map, entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

T_MOCK_F(void,
vm_entry_unlock_exclusive_and_destroy,
(vm_map_t map,
vm_map_entry_t entry),
(map, entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_UNLOCK);

	vm_entry_unlock_exclusive_and_destroy(map, entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_UNLOCK);
}

T_MOCK_F(bool,
vm_entry_try_lock_exclusive,
(vm_map_entry_t entry),
(entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);

	bool success = vm_entry_try_lock_exclusive(entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_LOCK |
	    FIBERS_YIELD_REASON_ERROR_IF(!success));

	return success;
}

T_MOCK_F(bool,
vm_entry_try_lock_shared,
(vm_map_entry_t entry),
(entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);

	bool success = vm_entry_try_lock_shared(entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_LOCK |
	    FIBERS_YIELD_REASON_ERROR_IF(!success));

	return success;
}

T_MOCK_F(bool,
vm_entry_lock_try_shared_to_exclusive,
(vm_map_entry_t entry),
(entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);

	bool success = vm_entry_lock_try_shared_to_exclusive(entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_LOCK |
	    FIBERS_YIELD_REASON_ERROR_IF(!success));

	return success;
}

T_MOCK_F(void,
vm_entry_lock_exclusive_to_shared,
(vm_map_entry_t entry),
(entry))
{
	may_yield(FIBERS_YIELD_REASON_MUTEX_WILL_LOCK);

	vm_entry_lock_exclusive_to_shared(entry);

	may_yield(FIBERS_YIELD_REASON_MUTEX_DID_LOCK);
}
