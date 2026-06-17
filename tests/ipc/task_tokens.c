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

/*
 * Tests for task token atomicity.
 *
 * rdar://170244624: ipc_kmsg_init_trailer_and_sign() called
 * task_get_sec_token() and task_get_audit_token() separately, which
 * could result in a "torn read" where the security token came from one
 * update and the audit token from another.
 *
 * rdar://169561861: the non-atomic 40-byte task_tokens write raced with
 * lockless Mach trailer reads, so euid+ruid or egid+rgid could be read
 * as a mismatched pair (one half from an old update, the other from a
 * new one).
 *
 * The fix stores euid+ruid and egid+rgid as 64-bit atomics so each pair
 * is always consistent, and constructs both tokens from these authoritative
 * fields.
 */

#include <darwintest.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdatomic.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc.task_tokens"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(true)
	);

typedef struct {
	mach_msg_header_t header;
	mach_msg_audit_trailer_t trailer;
} msg_with_audit_trailer_t;


T_DECL(task_tokens_basic,
    "Verify task tokens can be retrieved via task_info")
{
	kern_return_t kr;
	security_token_t sec_token;
	audit_token_t audit_token;
	mach_msg_type_number_t count;

	/* Get security token */
	count = TASK_SECURITY_TOKEN_COUNT;
	kr = task_info(mach_task_self(), TASK_SECURITY_TOKEN,
	    (task_info_t)&sec_token, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SECURITY_TOKEN)");

	/* Get audit token */
	count = TASK_AUDIT_TOKEN_COUNT;
	kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
	    (task_info_t)&audit_token, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_AUDIT_TOKEN)");

	/* Verify tokens match our process */
	T_EXPECT_EQ(sec_token.val[0], (uint32_t)getuid(),
	    "security token uid matches getuid()");
	T_EXPECT_EQ(audit_token.val[1], (uint32_t)geteuid(),
	    "audit token euid matches geteuid()");
	T_EXPECT_EQ(audit_token.val[3], (uint32_t)getuid(),
	    "audit token ruid matches getuid()");
	T_EXPECT_EQ(audit_token.val[5], (uint32_t)getpid(),
	    "audit token pid matches getpid()");
}

T_DECL(task_tokens_mach_msg,
    "Verify mach message trailer contains correct tokens")
{
	kern_return_t kr;
	mach_port_t port;
	msg_with_audit_trailer_t send_msg, recv_msg;

	/* Create a port */
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(), port, port,
	    MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right");

	/* Send a message to ourselves */
	memset(&send_msg, 0, sizeof(send_msg));
	send_msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    0, 0, 0);
	send_msg.header.msgh_size = sizeof(mach_msg_header_t);
	send_msg.header.msgh_remote_port = port;
	send_msg.header.msgh_local_port = MACH_PORT_NULL;

	kr = mach_msg(&send_msg.header, MACH_SEND_MSG,
	    send_msg.header.msgh_size, 0,
	    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg send");

	/* Receive with audit trailer */
	memset(&recv_msg, 0, sizeof(recv_msg));
	kr = mach_msg(&recv_msg.header,
	    MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
	    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
	    0, sizeof(recv_msg), port,
	    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg receive");

	/* Verify trailer tokens match our process */
	T_EXPECT_EQ(recv_msg.trailer.msgh_sender.val[0], (uint32_t)getuid(),
	    "trailer security token uid matches");
	T_EXPECT_EQ(recv_msg.trailer.msgh_audit.val[5], (uint32_t)getpid(),
	    "trailer audit token pid matches");

	/* Cleanup */
	kr = mach_port_destruct(mach_task_self(), port, -1, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");
}

/*
 * Stress test configuration
 */
#define STRESS_DURATION_SECS    5

struct stress_cred {
	uid_t euid;
	uid_t ruid;
	gid_t egid;
	gid_t rgid;
};

static mach_port_t stress_port;
static atomic_bool stress_stop;
static atomic_int stress_messages_checked;
static struct stress_cred stress_a, stress_b;

/*
 * Set credentials to the given stress_cred values.
 *
 * The order matters to preserve saved-set-user-ID = 0:
 *  1. seteuid(0)          — restore root so setregid() succeeds;
 *                            allowed because saved-uid is still 0.
 *  2. setregid(rgid, egid) — requires euid 0 for arbitrary values.
 *  3. setreuid(ruid, -1)  — change ruid only; since euid is still 0,
 *                            saved-uid is set to current euid = 0.
 *  4. seteuid(euid)       — change euid only; seteuid() does not
 *                            modify saved-uid, so it stays 0.
 *
 * This lets us call seteuid(0) on the next switch to get root back.
 * Using setreuid(ruid, euid) instead would set saved-uid = euid
 * (non-zero), making it impossible to restore root afterwards.
 */
static void
stress_set_creds(const struct stress_cred *c, bool restore_root)
{
	int ret;

	if (restore_root) {
		ret = seteuid(0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "seteuid(0)");
	}

	ret = setregid(c->rgid, c->egid);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "setregid");

	ret = setreuid(c->ruid, -1);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "setreuid");

	ret = seteuid(c->euid);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "seteuid");
}

static void *
token_writer_thread(void *arg __unused)
{
	bool use_a = true;

	while (!atomic_load(&stress_stop)) {
		struct stress_cred *c = use_a ? &stress_a : &stress_b;
		stress_set_creds(c, true);
		use_a = !use_a;
	}

	return NULL;
}

static void *
token_reader_thread(void *arg __unused)
{
	kern_return_t kr;
	msg_with_audit_trailer_t send_msg, recv_msg;

	while (!atomic_load(&stress_stop)) {
		/* Send a message */
		memset(&send_msg, 0, sizeof(send_msg));
		send_msg.header.msgh_bits = MACH_MSGH_BITS_SET(
			MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
		send_msg.header.msgh_size = sizeof(mach_msg_header_t);
		send_msg.header.msgh_remote_port = stress_port;
		send_msg.header.msgh_local_port = MACH_PORT_NULL;
		send_msg.header.msgh_id = 0x12345678;

		kr = mach_msg(&send_msg.header, MACH_SEND_MSG,
		    send_msg.header.msgh_size, 0,
		    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			continue;
		}

		/* Receive with audit trailer */
		memset(&recv_msg, 0, sizeof(recv_msg));
		kr = mach_msg(&recv_msg.header,
		    MACH_RCV_MSG |
		    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
		    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
		    0, sizeof(recv_msg), stress_port,
		    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			continue;
		}

		atomic_fetch_add(&stress_messages_checked, 1);

		security_token_t *sec = &recv_msg.trailer.msgh_sender;
		audit_token_t *audit = &recv_msg.trailer.msgh_audit;

		uint32_t sec_euid = sec->val[0];
		uint32_t sec_egid = sec->val[1];
		uint32_t audit_euid = audit->val[1];
		uint32_t audit_egid = audit->val[2];
		uint32_t audit_ruid = audit->val[3];
		uint32_t audit_rgid = audit->val[4];

		/*
		 * Check 1: security_token euid/egid must match
		 * audit_token euid/egid (cross-token consistency).
		 */
		T_QUIET; T_ASSERT_EQ_UINT(sec_euid, audit_euid,
		    "Cross-token torn: sec_euid %u != audit_euid %u",
		    sec_euid, audit_euid);
		T_QUIET; T_ASSERT_EQ_UINT(sec_egid, audit_egid,
		    "Cross-token torn: sec_egid %u != audit_egid %u",
		    sec_egid, audit_egid);

		/*
		 * Check 2: euid and ruid must be a valid pair.
		 * euid=0 with either ruid is a valid intermediate state
		 * (writer restores root euid before switching credentials).
		 */
		bool valid_uids =
		    (audit_euid == stress_a.euid && audit_ruid == stress_a.ruid) ||
		    (audit_euid == stress_b.euid && audit_ruid == stress_b.ruid) ||
		    (audit_euid == 0 && (audit_ruid == stress_a.ruid ||
		    audit_ruid == stress_b.ruid));
		T_QUIET; T_ASSERT_TRUE(valid_uids,
		    "Non valid euid/ruid pair: euid %u ruid %u",
		    audit_euid, audit_ruid);

		/*
		 * Check 3: egid and rgid must be a valid pair.
		 */
		bool valid_gids =
		    (audit_egid == stress_a.egid && audit_rgid == stress_a.rgid) ||
		    (audit_egid == stress_b.egid && audit_rgid == stress_b.rgid);
		T_QUIET; T_ASSERT_TRUE(valid_gids,
		    "Non valid egid/rgid pair: egid %u rgid %u",
		    audit_egid, audit_rgid);
	}

	return NULL;
}

T_DECL(task_tokens_stress,
    "Stress test for concurrent token updates",
    T_META_ASROOT(true))
{
	kern_return_t kr;
	pthread_t writer, reader;
	int ret;

	/*
	 * Set up two distinct credential sets to toggle between.
	 * Use values that are easily distinguishable so torn reads
	 * are obvious. As root, we can use setreuid/setregid freely.
	 */
	stress_a = (struct stress_cred){ .euid = 100, .ruid = 200, .egid = 300, .rgid = 400 };
	stress_b = (struct stress_cred){ .euid = 501, .ruid = 502, .egid = 503, .rgid = 504 };

	/* Create port for message passing */
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &stress_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(), stress_port, stress_port,
	    MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right");

	/* Initialize state */
	atomic_store(&stress_stop, false);
	atomic_store(&stress_messages_checked, 0);

	/* Setup credentials before the first read. */
	stress_set_creds(&stress_a, false);

	/* Start threads */
	ret = pthread_create(&writer, NULL, token_writer_thread, NULL);
	T_ASSERT_POSIX_ZERO(ret, "pthread_create writer");

	ret = pthread_create(&reader, NULL, token_reader_thread, NULL);
	T_ASSERT_POSIX_ZERO(ret, "pthread_create reader");

	/* Let them run for a while */
	sleep(STRESS_DURATION_SECS);

	/* Stop threads */
	atomic_store(&stress_stop, true);

	pthread_join(writer, NULL);
	pthread_join(reader, NULL);

	/* Report results */
	int messages = atomic_load(&stress_messages_checked);

	T_LOG("Checked %d messages over %d seconds", messages, STRESS_DURATION_SECS);
	T_EXPECT_GT(messages, 0, "Should have checked at least one message");

	/* Cleanup */
	kr = mach_port_destruct(mach_task_self(), stress_port, -1, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct");
}
