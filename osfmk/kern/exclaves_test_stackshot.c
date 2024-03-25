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

#if DEBUG || DEVELOPMENT

#include <kern/exclaves_test_stackshot.h>
#include <kern/thread.h>

static const char*
testpoint_name(tp_id_t testpoint)
{
	switch (testpoint) {
	case TP_BLOCK_START_STACKSHOT:
		return "TP_BLOCK_START_STACKSHOT";
	case TP_WAIT_START_STACKSHOT:
		return "TP_WAIT_START_STACKSHOT";
	case TP_UPCALL:
		return "TP_UPCALL";
	case TP_START_COLLECTION:
		return "TP_START_COLLECTION";
	case TP_AST:
		return "TP_AST";
	case TP_STACKSHOT_DONE:
		return "TP_STACKSHOT_DONE";
	default:
		return "<unknown>";
	}
}

/*
 *
 *   STACKSHOT_LONG_UPCALL scenario
 *   ==============================
 *   Test return from upcall of already collected thread.
 *
 *   stackshot thread (main test thread)
 |
 |
 |   [BLOCK_START_STACKSHOT @ userspace]
 |   set WAIT_START_STACKSHOT tag to to wait
 |
 |
 |   create exclaves thread --------------------------------------> exclaves thread starts
 |                                                                  |
 |                                                                  |
 |   start stackshot                                                call c-hello-world exclave service
 |                                                                  |
 |                                                                  |
 |   [WAIT_START_STACKSHOT]                                         upcall into xnu
 |   waits until exclave thread hangs in upcall                     |
 |                                                                  |
 |                                                                  [UPCALL]
 |   unblock <----------------------------------------------------- release stackshot thread and wait in upcall
 |                                                                  until it's flagged for AST check
 |                                                                  |
 |   stackshot collection                                           |
 |                                                                  |
 |                                                                  |
 |   [STACKSHOT_DONE] --------------------------------------------> stop hanging in upcall and return
 |                                                                  |
 |                                                                  |
 |   compose kcdata                                                 done
 |
 |
 |   check kcdata in userspace
 */

void
tp_call_stackshot_long_upcall(tp_id_t testpoint, tp_val_t __unused val)
{
	printf("tp_call(STACKSHOT_LONG_UPCALL/%s) pre-start\n", testpoint_name(testpoint));
	// do nothing for unsupported testpoints
	switch (testpoint) {
	case TP_BLOCK_START_STACKSHOT:
		break;
	case TP_WAIT_START_STACKSHOT:
		break;
	case TP_UPCALL:
		break;
	case TP_STACKSHOT_DONE:
		break;
	default:
		return;
	}

	printf("tp_call(STACKSHOT_LONG_UPCALL/%s) start\n", testpoint_name(testpoint));
	lck_mtx_lock(&tp_mtx);
	switch (testpoint) {
	case TP_BLOCK_START_STACKSHOT:         // stackshot thread, from userspace
		tp_block(TP_WAIT_START_STACKSHOT);
		break;
	case TP_WAIT_START_STACKSHOT:         // stackshot thread
		tp_wait(testpoint);
		break;
	case TP_UPCALL:         // upcall thread, block itself and start stackshot
		tp_relay(testpoint, TP_WAIT_START_STACKSHOT);
		break;
	case TP_STACKSHOT_DONE:         // release a thread hanging in upcall
		tp_unblock(TP_UPCALL);
		break;
	default:
		break;
	}
	lck_mtx_unlock(&tp_mtx);
	printf("tp_call(STACKSHOT_LONG_UPCALL/%s) finish\n", testpoint_name(testpoint));
}

/*
 *
 *   STACKSHOT_UPCALL scenario
 *   =========================
 *   Send one thread into upcall and start exclaves collection when the thread starts waiting on AST.
 *
 *   stackshot thread (main test thread)
 |
 |
 |   [BLOCK_START_STACKSHOT @ userspace]
 |   set WAIT_START_STACKSHOT tag to to wait
 |
 |
 |   create exclaves thread --------------------------------------> exclaves thread starts
 |                                                                  |
 |                                                                  |
 |   start stackshot                                                call c-hello-world exclave service
 |                                                                  |
 |                                                                  |
 |   [WAIT_START_STACKSHOT]                                         upcall into xnu
 |   waits until exclave thread hangs in upcall                     |
 |                                                                  |
 |   unblock <----------------------------------------------------- [UPCALL]
 |                                                                  release stackshot thread and wait in upcall
 |                                                                  |
 |   collect xnu (without exclaves) mark exclave threads blocked    |
 |                                                                  |
 |                                                                  |
 |   [START_COLLECTION] ------------------------------------------> stop hanging in upcall and try to return
 |   block here, just before exclave threads collection             |
 |                                                                  |
 |                                                                  |
 |   unblock <----------------------------------------------------- [TP_AST]
 |   collection pending                                             just before AST flag check
 |                                                                  |
 |                                                                  |
 |                                                                  wait on AST check (assuming collection takes some time)
 |                                                                  |
 |                                                                  |
 |   collection done ---------------------------------------------> unblock AST
 |                                                                  |
 |                                                                  |
 |   compose kcdata                                                 done
 |
 |
 |   check kcdata in userspace
 */

void
tp_call_stackshot_upcall(tp_id_t testpoint, tp_val_t __unused val)
{
	// do nothing for unsupported testpoints
	switch (testpoint) {
	case TP_BLOCK_START_STACKSHOT:
		break;
	case TP_WAIT_START_STACKSHOT:
		break;
	case TP_UPCALL:
		break;
	case TP_START_COLLECTION:
		break;
	case TP_AST:
		break;
	default:
		return;
	}

	printf("tp_call(STACKSHOT_UPCALL/%s) start\n", testpoint_name(testpoint));
	lck_mtx_lock(&tp_mtx);
	switch (testpoint) {
	case TP_BLOCK_START_STACKSHOT:         // stackshot thread, from userspace
		tp_block(TP_WAIT_START_STACKSHOT);
		break;
	case TP_WAIT_START_STACKSHOT:         // stackshot thread
		tp_wait(testpoint);
		break;
	case TP_UPCALL:         // upcall thread, block itself and start stackshot
		tp_relay(testpoint, TP_WAIT_START_STACKSHOT);
		break;
	case TP_START_COLLECTION:         // stackshot thread, just before exclaves collection start
		tp_relay(testpoint, TP_UPCALL);
		break;
	case TP_AST:         // upcall thread, just before it starts wait for AST
		tp_unblock(TP_START_COLLECTION);
		break;
	default:
		break;
	}
	lck_mtx_unlock(&tp_mtx);
	printf("tp_call(STACKSHOT_UPCALL/%s) finish\n", testpoint_name(testpoint));
}

#endif /* DEBUG || DEVELOPMENT */
