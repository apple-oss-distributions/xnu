/*
 * Copyright (c) 2024 Apple Computer, Inc. All rights reserved.
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
#include <stdbool.h>
#include <stdint.h>
#include <sys/_types/_pid_t.h>

#pragma once

#if !XNU_KERNEL_PRIVATE
#error "Including xnu-private header in unexpected target"
#endif /* !XNU_KERNEL_PRIVATE */

__BEGIN_DECLS

/* TODO: migrate other xnu-private interfaces from kern_memorystatus.h */

/*
 * Return the minimum number of available pages jetsam requires before it
 * begins killing non-idle processes. This is useful for some pageout
 * mechanisms to avoid deadlock.
 */
extern uint32_t memorystatus_get_critical_page_shortage_threshold(void);

/*
 * Return the minimum number of available pages jetsam requires before it
 * begins killing idle processes. This is consumed by the vm pressure
 * notification system in the absence of the compressor.
 */
extern uint32_t memorystatus_get_idle_exit_page_shortage_threshold(void);

/*
 * Return the minimum number of available pages jetsam requires before it
 * begins killing processes which have violated their soft memory limit. This
 * is consumed by the vm pressure notification system in the absence of the
 * compressor.
 */
extern uint32_t memorystatus_get_soft_memlimit_page_shortage_threshold(void);

/*
 * Return the minumum number of available pages jetsam requires before it
 * begins reaping long-idle processes.
 */
extern uint32_t memorystatus_get_reaper_page_shortage_threshold(void);

/*
 * Return the current number of available pages in the system.
 */
extern uint32_t memorystatus_get_available_page_count(void);

/*
 * Set the available page count and consider engaging response measures (e.g.
 * waking jetsam thread/pressure-notification thread).
 */
extern void memorystatus_update_available_page_count(uint32_t available_pages);

/*
 * Override fast-jetsam support. If override is enabled, fast-jetsam will be
 * disabled.
 */
extern void memorystatus_fast_jetsam_override(bool enable_override);

/*
 * Callout to jetsam. If pid is -1, we wake up the memorystatus thread to do asynchronous kills.
 * For any other pid we try to kill that process synchronously.
 */
extern bool memorystatus_kill_on_zone_map_exhaustion(pid_t pid);

/*
 * Kill a single process due to compressor space shortage.
 */
extern bool memorystatus_kill_on_VM_compressor_space_shortage(bool async);

/*
 * Asynchronously kill a single process due to VM Pageout Starvation (i.e.
 * a "stuck" external pageout thread).
 */
extern void memorystatus_kill_on_vps_starvation(void);

/*
 * Synchronously kill a single process due to vnode exhaustion
 */
extern bool memorystatus_kill_on_vnode_exhaustion(void);

/*
 * Wake up the memorystatus thread so it can do async kills.
 * The memorystatus thread will keep killing until the system is
 * considered healthy.
 */
extern void memorystatus_thread_wake(void);

/*
 * Respond to compressor exhaustion by waking the jetsam thread or
 * synchronously invoking a no-paging-space action.
 */
extern void memorystatus_respond_to_compressor_exhaustion(void);

/*
 * Respond to swap exhaustion by waking the jetsam thread or
 * synchronously invoking a no-paging-space action.
 */
extern void memorystatus_respond_to_swap_exhaustion(void);

__END_DECLS
