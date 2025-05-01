/*
 * Copyright (c) 2012-2024 Apple Inc. All rights reserved.
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

/*
 * Boot Profiling
 *
 * The boot-profiling support is a mechanism to sample activity happening on the
 * system during boot. This mechanism sets up a periodic timer and on every timer fire,
 * captures a full backtrace into the boot profiling buffer. This buffer can be pulled
 * out and analyzed from user-space. It is turned on using the following boot-args:
 * "bootprofile_buffer_size" specifies the size of the boot profile buffer
 * "bootprofile_interval_ms" specifies the interval for the profiling timer
 *
 * Process Specific Boot Profiling
 *
 * The boot-arg "bootprofile_proc_name" can be used to specify a certain
 * process that needs to profiled during boot. Setting this boot-arg changes
 * the way stackshots are captured. At every timer fire, the code looks at the
 * currently running process and takes a stackshot only if the requested process
 * is on-core (which makes it unsuitable for MP systems).
 *
 * Trigger Events
 *
 * The boot-arg "bootprofile_type=boot" starts the timer during early boot. Using
 * "wake" starts the timer at AP wake from suspend-to-RAM.
 */

#include <stdint.h>
#include <vm/vm_kern_xnu.h>
#include <kern/locks.h>
#include <kern/timer_call.h>
#include <kern/telemetry.h>
#include <pexpert/pexpert.h>

extern char *proc_name_address(void *p);
extern int proc_selfpid(void);

#define BOOTPROFILE_MAX_BUFFER_SIZE (64*1024*1024) /* see also COPYSIZELIMIT_PANIC */

vm_offset_t         bootprofile_buffer = 0;
uint32_t            bootprofile_buffer_current_position = 0;
uint64_t            bootprofile_interval_abs = 0;
uint64_t            bootprofile_next_deadline = 0;
uint32_t            bootprofile_all_procs = 0;
uint64_t            bootprofile_delta_since_timestamp = 0;
LCK_GRP_DECLARE(bootprofile_lck_grp, "bootprofile_group");
LCK_MTX_DECLARE(bootprofile_mtx, &bootprofile_lck_grp);

enum {
	kBootProfileDisabled = 0,
	kBootProfileStartTimerAtBoot,
	kBootProfileStartTimerAtWake
} bootprofile_type = kBootProfileDisabled;

static timer_call_data_t        bootprofile_timer_call_entry;

#define BOOTPROFILE_LOCK() do { lck_mtx_lock(&bootprofile_mtx); } while(0)
#define BOOTPROFILE_TRY_SPIN_LOCK() lck_mtx_try_lock_spin(&bootprofile_mtx)
#define BOOTPROFILE_UNLOCK() do { lck_mtx_unlock(&bootprofile_mtx); } while(0)

static void bootprofile_timer_call(
	timer_call_param_t      param0,
	timer_call_param_t      param1);

TUNABLE(uint32_t, bootprofile_buffer_size, "bootprofile_buffer_size", 0);
TUNABLE(uint32_t, bootprofile_interval_ms, "bootprofile_interval_ms", 0);
TUNABLE(uint64_t, bootprofile_stackshot_flags, "bootprofile_stackshot_flags", 0);
TUNABLE_STR(bootprofile_proc_name, 17, "bootprofile_proc_name", "");
TUNABLE_STR(bootprofile_type_name, 5, "bootprofile_type", "");

static void
_bootprofile_init(void)
{
	if (bootprofile_buffer_size > BOOTPROFILE_MAX_BUFFER_SIZE) {
		bootprofile_buffer_size = BOOTPROFILE_MAX_BUFFER_SIZE;
	}

	if (bootprofile_proc_name[0] == '\0') {
		bootprofile_all_procs = 1;
	}

	if (0 == strcmp(bootprofile_type_name, "boot")) {
		bootprofile_type = kBootProfileStartTimerAtBoot;
	} else if (0 == strcmp(bootprofile_type_name, "wake")) {
		bootprofile_type = kBootProfileStartTimerAtWake;
	} else {
		bootprofile_type = kBootProfileDisabled;
	}

	clock_interval_to_absolutetime_interval(bootprofile_interval_ms, NSEC_PER_MSEC, &bootprofile_interval_abs);

	/* Both boot args must be set to enable */
	if ((bootprofile_type == kBootProfileDisabled) || (bootprofile_buffer_size == 0) || (bootprofile_interval_abs == 0)) {
		return;
	}

	kern_return_t ret = kmem_alloc(kernel_map, &bootprofile_buffer, bootprofile_buffer_size,
	    KMA_DATA | KMA_ZERO | KMA_PERMANENT, VM_KERN_MEMORY_DIAG);
	if (ret != KERN_SUCCESS) {
		kprintf("Boot profile: Allocation failed: %d\n", ret);
		return;
	}

	kprintf("Boot profile: Sampling %s once per %u ms at %s\n",
	    bootprofile_all_procs ? "all procs" : bootprofile_proc_name, bootprofile_interval_ms,
	    bootprofile_type == kBootProfileStartTimerAtBoot ? "boot" : (bootprofile_type == kBootProfileStartTimerAtWake ? "wake" : "unknown"));

	timer_call_setup(&bootprofile_timer_call_entry,
	    bootprofile_timer_call,
	    NULL);

	if (bootprofile_type == kBootProfileStartTimerAtBoot) {
		bootprofile_next_deadline = mach_absolute_time() + bootprofile_interval_abs;
		timer_call_enter_with_leeway(&bootprofile_timer_call_entry,
		    NULL,
		    bootprofile_next_deadline,
		    0,
		    TIMER_CALL_SYS_NORMAL,
		    false);
	}
}

STARTUP(SYSCTL, STARTUP_RANK_FIRST, _bootprofile_init);

void
bootprofile_wake_from_sleep(void)
{
	if (bootprofile_type == kBootProfileStartTimerAtWake) {
		bootprofile_next_deadline = mach_absolute_time() + bootprofile_interval_abs;
		timer_call_enter_with_leeway(&bootprofile_timer_call_entry,
		    NULL,
		    bootprofile_next_deadline,
		    0,
		    TIMER_CALL_SYS_NORMAL,
		    false);
	}
}

static void
bootprofile_timer_call(
	timer_call_param_t      param0 __unused,
	timer_call_param_t      param1 __unused)
{
	unsigned retbytes = 0;
	int pid_to_profile = -1;

	if (!BOOTPROFILE_TRY_SPIN_LOCK()) {
		goto reprogram;
	}

	/* Check if process-specific boot profiling is turned on */
	if (!bootprofile_all_procs) {
		/*
		 * Since boot profiling initializes really early in boot, it is
		 * possible that at this point, the task/proc is not initialized.
		 * Nothing to do in that case.
		 */

		if ((current_task() != NULL) && (get_bsdtask_info(current_task()) != NULL) &&
		    (0 == strncmp(bootprofile_proc_name, proc_name_address(get_bsdtask_info(current_task())), 17))) {
			pid_to_profile = proc_selfpid();
		} else {
			/*
			 * Process-specific boot profiling requested but the on-core process is
			 * something else. Nothing to do here.
			 */
			BOOTPROFILE_UNLOCK();
			goto reprogram;
		}
	}

	/* initiate a stackshot with whatever portion of the buffer is left */
	if (bootprofile_buffer_current_position < bootprofile_buffer_size) {
		uint64_t flags = STACKSHOT_KCDATA_FORMAT | STACKSHOT_TRYLOCK | STACKSHOT_SAVE_LOADINFO
		    | STACKSHOT_GET_GLOBAL_MEM_STATS;
#if defined(XNU_TARGET_OS_OSX)
		flags |= STACKSHOT_SAVE_KEXT_LOADINFO;
#endif


		/* OR on flags specified in boot-args */
		flags |= bootprofile_stackshot_flags;
		if ((flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) && (bootprofile_delta_since_timestamp == 0)) {
			/* Can't take deltas until the first one */
			flags &= ~STACKSHOT_COLLECT_DELTA_SNAPSHOT;
		}

		uint64_t timestamp = 0;
		if (bootprofile_stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) {
			timestamp = mach_absolute_time();
		}

		kern_return_t r = stack_snapshot_from_kernel(
			pid_to_profile, (void *)(bootprofile_buffer + bootprofile_buffer_current_position),
			bootprofile_buffer_size - bootprofile_buffer_current_position,
			flags, bootprofile_delta_since_timestamp, 0, &retbytes);

		/*
		 * We call with STACKSHOT_TRYLOCK because the stackshot lock is coarser
		 * than the bootprofile lock.  If someone else has the lock we'll just
		 * try again later.
		 */

		if (r == KERN_LOCK_OWNED) {
			BOOTPROFILE_UNLOCK();
			goto reprogram;
		}

		if (bootprofile_stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT &&
		    r == KERN_SUCCESS) {
			bootprofile_delta_since_timestamp = timestamp;
		}

		bootprofile_buffer_current_position += retbytes;
	}

	BOOTPROFILE_UNLOCK();

	/* If we didn't get any data or have run out of buffer space, stop profiling */
	if ((retbytes == 0) || (bootprofile_buffer_current_position == bootprofile_buffer_size)) {
		return;
	}


reprogram:
	/* If the user gathered the buffer, no need to keep profiling */
	if (bootprofile_interval_abs == 0) {
		return;
	}

	clock_deadline_for_periodic_event(bootprofile_interval_abs,
	    mach_absolute_time(),
	    &bootprofile_next_deadline);
	timer_call_enter_with_leeway(&bootprofile_timer_call_entry,
	    NULL,
	    bootprofile_next_deadline,
	    0,
	    TIMER_CALL_SYS_NORMAL,
	    false);
}

void
bootprofile_get(void **buffer, uint32_t *length)
{
	BOOTPROFILE_LOCK();
	*buffer = (void*) bootprofile_buffer;
	*length = bootprofile_buffer_current_position;
	BOOTPROFILE_UNLOCK();
}

int
bootprofile_gather(user_addr_t buffer, uint32_t *length)
{
	int result = 0;

	BOOTPROFILE_LOCK();

	if (bootprofile_buffer == 0) {
		*length = 0;
		goto out;
	}

	if (*length < bootprofile_buffer_current_position) {
		result = KERN_NO_SPACE;
		goto out;
	}

	if ((result = copyout((void *)bootprofile_buffer, buffer,
	    bootprofile_buffer_current_position)) != 0) {
		*length = 0;
		goto out;
	}
	*length = bootprofile_buffer_current_position;

	/* cancel future timers */
	bootprofile_interval_abs = 0;

out:

	BOOTPROFILE_UNLOCK();

	return result;
}
