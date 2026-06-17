/*
 * Copyright (c) 2026 Apple Computer, Inc. All rights reserved.
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
 * sysv_msgctl_race.c — Test for msgctl(IPC_SET) TOCTOU race (rdar://172502094)
 *
 * Verifies that msgctl(IPC_SET) does not corrupt a queue that was
 * freed and reallocated while IPC_SET is in progress. The fix holds
 * the SYSV_MSG_SUBSYS lock through copyin, consistent with how
 * sysv_sem.c and sysv_shm.c handle IPC_SET.
 *
 * The test forks a victim process and races IPC_SET + IPC_RMID +
 * msgget across 100 iterations. If IPC_SET ever writes attacker
 * values to a victim's queue, the test fails.
 */

#include <darwintest.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(true));

#define NUM_ITERATIONS    100
#define ATTACKER_UID      31337
#define ATTACKER_GID      31337
#define ATTACKER_MODE     0777
#define NUM_FILLER_QUEUES 10

struct shared_state {
	_Atomic int stop_flag;
	_Atomic int race_won;
	_Atomic long victim_checks;

	_Atomic int target_msqid;
	_Atomic int target_ready;
	_Atomic int do_delete;
};

static struct shared_state *shared;

/*
 * Attacker IPC_SET thread: continuously tries to overwrite the
 * target queue's uid/gid/mode with attacker values.
 */
static void *
attacker_set_thread(void *arg)
{
	(void)arg;
	struct msqid_ds buf;

	memset(&buf, 0, sizeof(buf));
	buf.msg_perm.uid = ATTACKER_UID;
	buf.msg_perm.gid = ATTACKER_GID;
	buf.msg_perm.mode = ATTACKER_MODE;
	buf.msg_qbytes = 2048;

	while (!atomic_load(&shared->stop_flag)) {
		if (atomic_load(&shared->target_ready)) {
			int msqid = atomic_load(&shared->target_msqid);
			if (msqid != -1) {
				msgctl(msqid, IPC_SET, &buf);
			}
		}
	}
	return NULL;
}

/*
 * Attacker IPC_RMID thread: continuously tries to delete the
 * target queue to free its slot for reuse.
 */
static void *
attacker_rmid_thread(void *arg)
{
	(void)arg;

	while (!atomic_load(&shared->stop_flag)) {
		if (atomic_load(&shared->do_delete)) {
			int msqid = atomic_load(&shared->target_msqid);
			if (msqid != -1) {
				msgctl(msqid, IPC_RMID, NULL);
			}
		}
	}
	return NULL;
}

/*
 * Victim process (child).
 *
 * Continuously creates queues and checks if their ownership was
 * corrupted to the attacker's values. Any corruption proves the
 * race was exploited across process boundaries.
 */
static void __attribute__((noreturn))
victim_process(void)
{
	uid_t my_uid = getuid();
	struct msqid_ds buf;
	int corrupted = 0;

	while (!atomic_load(&shared->stop_flag)) {
		int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
		if (msqid == -1) {
			usleep(100);
			continue;
		}

		if (msgctl(msqid, IPC_STAT, &buf) == 0) {
			atomic_fetch_add(&shared->victim_checks, 1);

			if (buf.msg_perm.uid == ATTACKER_UID &&
			    my_uid != ATTACKER_UID) {
				atomic_store(&shared->race_won, 1);
				atomic_store(&shared->stop_flag, 1);
				corrupted = 1;
			}
		}

		msgctl(msqid, IPC_RMID, NULL);

		if (corrupted) {
			break;
		}
	}

	_exit(corrupted ? 1 : 0);
}

T_DECL(sysv_msgctl_ipc_set_race,
    "Verify msgctl(IPC_SET) does not corrupt a reused queue slot (rdar://172502094)",
    T_META_ASROOT(true),
    T_META_ENABLED(TARGET_OS_OSX))
{
#if !TARGET_OS_OSX
	T_SKIP("msgctl is only available on macos");
#endif

	pthread_t threads[4];
	int filler_queues[NUM_FILLER_QUEUES];
	int num_fillers = 0;
	int ret;

	shared = mmap(NULL, sizeof(*shared),
	    PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	T_ASSERT_NE(shared, MAP_FAILED, "mmap shared state");

	atomic_store(&shared->stop_flag, 0);
	atomic_store(&shared->race_won, 0);
	atomic_store(&shared->victim_checks, 0);
	atomic_store(&shared->target_msqid, -1);
	atomic_store(&shared->target_ready, 0);
	atomic_store(&shared->do_delete, 0);

	/* Pre-fill some queue slots for predictable index reuse */
	for (int i = 0; i < NUM_FILLER_QUEUES; i++) {
		filler_queues[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
		if (filler_queues[i] == -1) {
			T_LOG("Filler queue allocation stopped at %d: %s",
			    i, strerror(errno));
			break;
		}
		num_fillers++;
	}
	T_LOG("Allocated %d filler queues", num_fillers);

	/* Fork victim process */
	pid_t victim_pid = fork();
	T_ASSERT_POSIX_SUCCESS(victim_pid, "fork victim");

	if (victim_pid == 0) {
		victim_process();
		/* not reached */
	}

	T_LOG("Attacker PID %d, victim PID %d", getpid(), victim_pid);

	/* Start attacker threads */
	ret = pthread_create(&threads[0], NULL, attacker_set_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create set_thread 0");
	ret = pthread_create(&threads[1], NULL, attacker_set_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create set_thread 1");
	ret = pthread_create(&threads[2], NULL, attacker_rmid_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create rmid_thread 0");
	ret = pthread_create(&threads[3], NULL, attacker_rmid_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create rmid_thread 1");

	for (int i = 0; i < NUM_ITERATIONS && !atomic_load(&shared->stop_flag); i++) {
		int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
		if (msqid == -1) {
			usleep(100);
			continue;
		}
		atomic_store(&shared->target_msqid, msqid);

		atomic_store(&shared->target_ready, 1);
		atomic_store(&shared->do_delete, 1);

		/* Let threads and victim race */
		usleep(1000);

		atomic_store(&shared->target_ready, 0);
		atomic_store(&shared->do_delete, 0);

		msgctl(msqid, IPC_RMID, NULL);
		atomic_store(&shared->target_msqid, -1);
	}

	atomic_store(&shared->stop_flag, 1);

	for (int i = 0; i < 4; i++) {
		ret = pthread_join(threads[i], NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_join thread %d", i);
	}

	int status;
	ret = waitpid(victim_pid, &status, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "waitpid victim");

	/* Cleanup filler queues */
	for (int i = 0; i < num_fillers; i++) {
		if (filler_queues[i] != -1) {
			msgctl(filler_queues[i], IPC_RMID, NULL);
		}
	}

	T_LOG("Victim performed %ld ownership checks",
	    atomic_load(&shared->victim_checks));

	T_ASSERT_GT_LONG(atomic_load(&shared->victim_checks), 0L,
	    "Victim performed at least one ownership check");

	T_ASSERT_EQ(atomic_load(&shared->race_won), 0,
	    "Victim queue ownership must never be corrupted by attacker's IPC_SET");

	ret = munmap(shared, sizeof(*shared));
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "munmap shared state");
}

T_DECL(sysv_msgctl_ipc_set_copyin_fault,
    "Verify we unlock the msqid global lock after copyin failed",
    T_META_ASROOT(true),
    T_META_ENABLED(TARGET_OS_OSX))
{
#if !TARGET_OS_OSX
	T_SKIP("msgctl is only available on macos");
#endif

	int msqid;
	struct msqid_ds buf;
	int ret;

	msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	T_ASSERT_POSIX_SUCCESS(msqid, "msgget create queue");

	/* Pass an invalid pointer — should fail with EFAULT */
	ret = msgctl(msqid, IPC_SET, (struct msqid_ds *)(uintptr_t)0x1);
	T_ASSERT_POSIX_FAILURE(ret, EFAULT,
	    "msgctl IPC_SET with invalid pointer returns EFAULT");

	/* Verify that we unlock after copyin failed */
	ret = msgctl(msqid, IPC_STAT, &buf);
	T_ASSERT_POSIX_SUCCESS(ret, "msgctl IPC_STAT after fault");

	ret = msgctl(msqid, IPC_RMID, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "msgctl IPC_RMID cleanup");
}
