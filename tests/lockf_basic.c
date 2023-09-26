/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
 */

#define PRIVATE 1 /* Needed for some F_OFD_* definitions */
#include <fcntl.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdatomic.h>

#ifndef O_CLOFORK
#define O_CLOFORK       0x08000000
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.locks"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("locks"),
	T_META_OWNER("tim_marsland"),   // with thanks to Peter Rutenbar
	T_META_RUN_CONCURRENTLY(TRUE));

enum lock_flags {
	EXCL = 1,
	WAIT = 2,
	UNLOCK = 4,
};

enum lock_type {
	TYPE_FLOCK = 0,
	TYPE_POSIX = 1,
	TYPE_OFD = 2,
};

static int
ofd_get(struct flock *fl,
    int fd, off_t start, off_t len, pid_t pid, uint32_t flags)
{
	fl->l_start = start;
	fl->l_len = len;
	fl->l_pid = pid;
	fl->l_type = (flags & EXCL) ? F_WRLCK : F_RDLCK;
	fl->l_whence = SEEK_SET;
	return fcntl(fd, (pid == -1) ? F_OFD_GETLK : F_OFD_GETLKPID, fl);
}

static int
posix_get(struct flock *fl,
    int fd, off_t start, off_t len, pid_t pid, uint32_t flags)
{
	fl->l_start = start;
	fl->l_len = len;
	fl->l_pid = pid;
	fl->l_type = (flags & EXCL) ? F_WRLCK : F_RDLCK;
	fl->l_whence = SEEK_SET;
	return fcntl(fd, (pid == -1) ? F_GETLK : F_GETLKPID, fl);
}

static int
posix_lock(int fd, off_t start, off_t len, uint32_t flags)
{
	struct flock fl = {
		.l_start = start,
		.l_len = len,
		.l_pid = -1,
		.l_type = (flags & EXCL) ? F_WRLCK : F_RDLCK,
		.l_whence = SEEK_SET,
	};
	return fcntl(fd, (flags & WAIT) ? F_SETLKW : F_SETLK, &fl);
}

static int
ofd_lock(int fd, off_t start, off_t len, uint32_t flags)
{
	struct flock fl = {
		.l_start = start,
		.l_len = len,
		.l_pid = -1,
		.l_type = (flags & EXCL) ? F_WRLCK : F_RDLCK,
		.l_whence = SEEK_SET,
	};
	return fcntl(fd, (flags & WAIT) ? F_OFD_SETLKW : F_OFD_SETLK, &fl);
}

static int
posix_unlock(int fd, off_t start, off_t len)
{
	struct flock fl = {
		.l_start = start,
		.l_len = len,
		.l_pid = -1,
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
	};
	return fcntl(fd, F_SETLK, &fl);
}

static int
ofd_unlock(int fd, off_t start, off_t len)
{
	struct flock fl = {
		.l_start = start,
		.l_len = len,
		.l_pid = -1,
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
	};
	return fcntl(fd, F_OFD_SETLK, &fl);
}

/* Is the given flock equal to the given arguments */
static bool
flequal(struct flock *fl, off_t start, off_t len, pid_t pid, int flags)
{
	if (start == fl->l_start && len == fl->l_len && pid == fl->l_pid) {
		if (flags == EXCL && fl->l_type == F_WRLCK) {
			return true;
		} else if (flags == UNLOCK && fl->l_type == F_UNLCK) {
			return true;
		} else if (flags == 0 && fl->l_type == F_RDLCK) {
			return true;
		}
	}
	T_LOG("flequal: %lld %lld %d %x %x\n",
	    fl->l_start, fl->l_len, fl->l_pid, fl->l_type, fl->l_whence);
	return false;
}

typedef struct {
	pthread_t thread;
	int fd, err;
	bool complete;
	enum lock_type lock_type;
	uint32_t flags;
	off_t start, end;
} lock_thread_state_t;

static void *
lock_thread(
	void *arg)
{
	lock_thread_state_t *lts = (lock_thread_state_t *)arg;

	switch (lts->lock_type) {
	case TYPE_FLOCK: {
		int op = (lts->flags & EXCL) ? LOCK_EX : LOCK_SH;
		op |= (lts->flags & WAIT) ? 0 : LOCK_NB;
		lts->err = flock(lts->fd, op) ? errno : 0;
		break;
	}
	case TYPE_POSIX:
		lts->err = posix_lock(lts->fd,
		    lts->start, lts->end, lts->flags) ? errno : 0;
		break;
	case TYPE_OFD:
		lts->err = ofd_lock(lts->fd,
		    lts->start, lts->end, lts->flags) ? errno : 0;
		break;
	}

	atomic_thread_fence(memory_order_acquire);
	lts->complete = true;
	atomic_thread_fence(memory_order_release);

	return NULL;
}

static bool
has_completed(lock_thread_state_t *lts)
{
	atomic_thread_fence(memory_order_acquire);
	const bool r = lts->complete;
	atomic_thread_fence(memory_order_release);
	return r;
}

static void
start_lock_thread(enum lock_type type, lock_thread_state_t *lts,
    int fd, off_t start, off_t end, uint32_t flags)
{
	lts->fd = fd;
	lts->err = 0;
	lts->complete = false;
	lts->lock_type = type;
	lts->flags = flags;
	lts->start = start;
	lts->end = end;

	pthread_create(&lts->thread, NULL, lock_thread, lts);
}

static void
random_pause(void)
{
	const useconds_t usec = rand() & (16384 - 1);
	usleep(usec + 1);
}

#define GET_CHECK( \
		str, fd, \
		get_start, get_len, get_flags, get_type, \
		chk_start, chk_len, chk_flags, chk_pid) \
	do { \
	        struct flock _fl; \
	        if (get_type == TYPE_OFD) { \
	                T_ASSERT_POSIX_SUCCESS(ofd_get(&_fl, fd, get_start, get_len, -1, get_flags), str " (ofd_get)"); \
	        } else { \
	                T_ASSERT_POSIX_SUCCESS(posix_get(&_fl, fd, get_start, get_len, -1, get_flags), str " (posix_get)"); \
	        } \
	        T_ASSERT_TRUE(flequal(&_fl, chk_start, chk_len, chk_pid, chk_flags), str " (flequal)"); \
	} while (0)

#define LOCK_AND_CHECK( \
		str, fd, \
		lck_start, lck_len, lck_flags, lock_type, \
		get_start, get_len, get_flags, get_type, \
		chk_start, chk_len, chk_flags, chk_pid) \
	do { \
	        if (lock_type == TYPE_OFD) { \
	                T_ASSERT_POSIX_SUCCESS(ofd_lock(fd, lck_start, lck_len, lck_flags), str " (ofd_lock)"); \
	        } else { \
	                T_ASSERT_POSIX_SUCCESS(posix_lock(fd, lck_start, lck_len, lck_flags), str " (posix_lock)"); \
	        } \
	        GET_CHECK(str, fd, get_start, get_len, get_flags, get_type, chk_start, chk_len, chk_flags, chk_pid); \
	} while (0)

#define UNLOCK_AND_CHECK( \
		str, fd, \
		lck_start, lck_len, unlock_type, \
		get_start, get_len, get_flags, get_type, \
		chk_start, chk_len, chk_flags, chk_pid) \
	do { \
	        if (unlock_type == TYPE_OFD) { \
	                T_ASSERT_POSIX_SUCCESS(ofd_unlock(fd, lck_start, lck_len), str " (ofd_unlock)"); \
	        } else { \
	                T_ASSERT_POSIX_SUCCESS(posix_unlock(fd, lck_start, lck_len), str " (posix_unlock)"); \
	        } \
	        GET_CHECK(str, fd, get_start, get_len, get_flags, get_type, chk_start, chk_len, chk_flags, chk_pid); \
	} while (0)

#define A_PATH "basic_lockf_a"
#define B_PATH "basic_lockf_b"

T_DECL(lockf_basic,
    "Basic test of flock/POSIX/OFD advisory file locks",
    T_META_CHECK_LEAKS(false))
{
	const char *tmpdir = dt_tmpdir();
	lock_thread_state_t lts[4];
	pid_t pid = getpid();
	int a, a_confined, b, b_confined;
	const off_t file_len = 0x10000;
	T_SETUPBEGIN;

	/* random sleeping to hunt for races */

	unsigned seed = (unsigned)pid;
	const char *p = getenv("LOCKF_BASIC_SRAND_SEED");
	if (p) {
		seed = (unsigned)atol(p);
	}
	srand(seed);

	/* Create two test files, a and b */
	T_ASSERT_POSIX_SUCCESS(chdir(tmpdir), "chdir(%s)", tmpdir);
	T_ASSERT_POSIX_SUCCESS((a = open(A_PATH, O_CREAT | O_RDWR, 0666)), "open(a)");
	T_ASSERT_POSIX_SUCCESS((b = open(B_PATH, O_CREAT | O_RDWR, 0666)), "open(b)");

	/* Give both files 64KiB */
	T_ASSERT_POSIX_SUCCESS(ftruncate(a, file_len), "truncate a");
	T_ASSERT_POSIX_SUCCESS(ftruncate(b, 0x10000), "truncate b");

	/* Open a/b again, but CONFINED this time */
	T_ASSERT_POSIX_SUCCESS((a_confined = open(A_PATH, O_CLOFORK | O_RDWR)), "open(a, O_CLOFORK)");
	T_ASSERT_POSIX_SUCCESS(fcntl(a_confined, F_SETCONFINED, 1), "F_SETCONFINED");
	T_ASSERT_POSIX_SUCCESS((b_confined = open(B_PATH, O_CLOFORK | O_RDWR)), "open(b, O_CLOFORK)");
	T_ASSERT_POSIX_SUCCESS(fcntl(b_confined, F_SETCONFINED, 1), "F_SETCONFINED");

	T_SETUPEND;

	/* Test all coalescence cases (non-upgrade/downgrade) */

	/*
	 *   [   ]
	 * + [   ]
	 * = [   ]
	 */
	T_ASSERT_POSIX_SUCCESS(posix_lock(a, 130, 20, 0), "Coalesce: initial posix lock");
	LOCK_AND_CHECK("Coalesce: equal", a,
	    130, 20, 0, TYPE_POSIX,                        /* POSIX-lock a, shared, from [100..199] */
	    0, 0, EXCL, TYPE_OFD,                        /* OFD-get the entire file, exclusively */
	    130, 20, 0, pid);                        /* The result should be: [100..199] is locked shared by our PID */

	/*
	 *   [   ]
	 * +     [   ]
	 * = [       ]
	 */
	LOCK_AND_CHECK("Coalesce: adjacent high", a,
	    150, 25, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    130, 45, 0, pid);

	/*
	 *       [   ]
	 * + [   ]
	 * = [       ]
	 */
	LOCK_AND_CHECK("Coalesce: adjacent low", a,
	    125, 5, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    125, 50, 0, pid);

	/*
	 *   [       ]
	 * +   [   ]
	 * = [       ]
	 */
	LOCK_AND_CHECK("Coalesce: subsume smaller", a,
	    150, 10, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    125, 50, 0, pid);

	/*
	 *     [   ]
	 * + [       ]
	 * = [       ]
	 */
	LOCK_AND_CHECK("Coalesce: subsume larger", a,
	    100, 100, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    100, 100, 0, pid);

	/*
	 *   [     ]
	 * + [          ]
	 * = [          ]
	 */
	LOCK_AND_CHECK("Coalesce: extend high", a,
	    100, 125, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    100, 125, 0, pid);

	/*
	 *        [     ]
	 * + [          ]
	 * = [          ]
	 */
	LOCK_AND_CHECK("Coalesce: extend low", a,
	    75, 150, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    75, 150, 0, pid);

	/*
	 *   [     ]
	 * +    [          ]
	 * = [             ]
	 */
	LOCK_AND_CHECK("Coalesce: overlap start", a,
	    50, 100, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    50, 175, 0, pid);

	/*
	 *           [     ]
	 * + [          ]
	 * = [             ]
	 */
	LOCK_AND_CHECK("Coalesce: overlap end", a,
	    150, 100, 0, TYPE_POSIX,
	    0, 0, EXCL, TYPE_OFD,
	    50, 200, 0, pid);

	/* Test all upgrade cases */

	/*
	 *   [  R  ]
	 * +       [  W  ]
	 * = [  R  |  W  ]
	 */
	LOCK_AND_CHECK("Upgrade: adjacent high not-coalesced", a,
	    250, 50, EXCL, TYPE_POSIX, /* Take the posix lock exclusively */
	    50, 250, 0, TYPE_OFD,      /* and OFD-get shared */
	    250, 50, EXCL, pid);

	/*
	 *         [  R  |  W  ]
	 * + [  W  ]
	 * = [  W  |  R  |  W  ]
	 */
	LOCK_AND_CHECK("Upgrade: adjacent low not-coalesced", a,
	    25, 25, EXCL, TYPE_POSIX,
	    25, 225, 0, TYPE_OFD,
	    25, 25, EXCL, pid);

	/*
	 *  25      50      250     300
	 *   [   W   |   R   |   W   ]
	 * +               [ W ]
	 *   [   W   |  R  |    W    ]
	 *  25      50    225       300
	 */
	LOCK_AND_CHECK("Upgrade: truncate shared-end, grow excl-start", a,
	    225, 50, EXCL, TYPE_POSIX,
	    50, 250, 0, TYPE_OFD,
	    225, 75, EXCL, pid);

	/*
	 *  25     50         225   300
	 *   [  W  |     R     |  W  ]
	 * +     [ W ]
	 * = [   W   |   R     |  W  ]
	 *  25      60        225   300
	 */
	LOCK_AND_CHECK("Upgrade: truncate shared-start, grow excl-end", a,
	    40, 20, EXCL, TYPE_POSIX,
	    0, 225, 0, TYPE_OFD,
	    25, 35, EXCL, pid);

	/*
	 *  25    60              225   300
	 *   [  W  |       R       |  W  ]
	 * +             [ W ]
	 * = [  W  |     | W |     |  W  ]
	 *  25    60    100 150   225   300
	 */
	LOCK_AND_CHECK("Upgrade: 3-way split", a,
	    100, 50, EXCL, TYPE_POSIX,
	    60, 165, 0, TYPE_OFD,
	    100, 50, EXCL, pid);

	/*
	 *  25    60    100 150   225   300
	 *   [  W  |     | W |     |  W  ]
	 * + [             W             ]
	 * = [             W             ]
	 *  25                          300
	 */
	LOCK_AND_CHECK("Upgrade: subsume multiple locks", a,
	    25, 275, EXCL, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    25, 275, EXCL, pid);

	/* Unlock / waiter-wakeup cases */

	/*
	 *  25              300
	 *   [       W       ]
	 * +               [W (wait)]
	 *                290      310
	 */
	start_lock_thread(TYPE_OFD, &lts[0], a, 290, 20, EXCL | WAIT); /* Wait on this lock in another thread */
	random_pause();
	T_ASSERT_FALSE(has_completed(&lts[0]), "Unlock: created waiting lock");

	/*
	 *  25              300
	 *   [       W       ]
	 * -                 [  -  ]
	 * = [       W       ]
	 *  25              300
	 */
	UNLOCK_AND_CHECK("Unlock: region with no locks", a,
	    300, 100, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    25, 275, EXCL, pid);
	T_ASSERT_FALSE(has_completed(&lts[0]), "Unlock: waiter still waiting");

	/*
	 *  25              300
	 *   [       W       ]
	 * -               [  -  ]
	 * = [      W      ]
	 *  25            250
	 */
	UNLOCK_AND_CHECK("Unlock: overlap end", a,
	    250, 100, TYPE_POSIX,
	    25, 1, 0, TYPE_OFD,
	    25, 225, EXCL, pid);

	/*
	 *  25            250
	 *   [      W      ]
	 *                   [  W  ]
	 *                  290   310
	 */

	while (!has_completed(&lts[0])) {
		random_pause();
	}
	T_ASSERT_TRUE(has_completed(&lts[0]), "Unlock: waiter woke up");
	T_ASSERT_POSIX_ZERO(lts[0].err, "Unlock: no err granting waiter");
	GET_CHECK("Unlock: waiter granted confirmation", a,
	    250, 100, 0, TYPE_POSIX,
	    290, 20, EXCL, -1); /* -1 because it's a non-CONFINED OFD lock (with no PID) */

	T_ASSERT_POSIX_SUCCESS(ofd_unlock(a, 290, 20), "Unlock: unlock that now-granted waiter");

	/*
	 *  25            250
	 *   [      W      ] 290   310
	 *                    [  W  ]
	 * -                  [  -  ]
	 * = [      W      ]
	 *  25            250
	 */
	UNLOCK_AND_CHECK("Unlock: equal range", a,
	    290, 20, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    25, 225, EXCL, pid);

	/*
	 *    25            250
	 *     [       W     ]
	 * - [ - ]
	 * =     [     W     ]
	 *      50          250
	 */
	UNLOCK_AND_CHECK("Unlock: overlap start", a,
	    0, 50, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    50, 200, EXCL, pid);

	/*
	 *  50          250
	 *   [     W     ]
	 * - [  ]
	 * =    [    W   ]
	 *     100      250
	 */
	UNLOCK_AND_CHECK("Unlock: start-aligned", a,
	    50, 50, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    100, 150, EXCL, pid);

	/*
	 *  100          250
	 *   [     W     ]
	 * -          [  ]
	 * = [   W    ]
	 *  100      200
	 */
	UNLOCK_AND_CHECK("Unlock: end-aligned", a,
	    200, 50, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    100, 100, EXCL, pid);

	/*
	 *  100             200
	 *   [       W       ]
	 * -       [   ]
	 * = [  W  ]   [  W  ]
	 *  100   125 175   200
	 */
	UNLOCK_AND_CHECK("Unlock: split", a,
	    125, 50, TYPE_POSIX,
	    0, 150, 0, TYPE_OFD,
	    100, 25, EXCL, pid);

	/* Check the tail-fragment too */
	GET_CHECK("Unlock: split (tail-check)", a,
	    125, 200, 0, TYPE_OFD,
	    175, 25, EXCL, pid);

	/*
	 *    100   125   175   200
	 *     [  W  ]     [  W  ]
	 * - [                     ]
	 * =        (no locks)
	 */
	UNLOCK_AND_CHECK("Unlock: multiple locks", a,
	    0, 0, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    0, 0, UNLOCK, -1);


	/*
	 * Downgrade / waiter-wakeup test:
	 * The only interesting different between this and upgrade is that waiting locks
	 * may now be granted. So let's test that...
	 */

	/*
	 *  Create this lock layout
	 *  0                                500
	 *  [                W                ]
	 *
	 *  0     100     200   300     400        600
	 *  [R(wait)]     [R(wait)]     [   R(wait)  ]
	 *
	 *      50                        450
	 *      [          R(wait)          ]
	 */

	LOCK_AND_CHECK("Downgrade: first lock", a,
	    0, 500, EXCL, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    0, 500, EXCL, pid);

	start_lock_thread(TYPE_OFD, &lts[0], a, 0, 100, WAIT);
	start_lock_thread(TYPE_OFD, &lts[1], a, 200, 100, WAIT);
	start_lock_thread(TYPE_OFD, &lts[2], a, 400, 200, WAIT);
	start_lock_thread(TYPE_OFD, &lts[3], a, 50, 400, WAIT);

	random_pause(); /* wait a bit to allow the lock threads to run */

	T_ASSERT_FALSE(has_completed(&lts[0]), "Downgrade: waiter 0 waiting");;
	T_ASSERT_FALSE(has_completed(&lts[1]), "Downgrade: waiter 1 waiting");
	T_ASSERT_FALSE(has_completed(&lts[2]), "Downgrade: waiter 2 waiting");
	T_ASSERT_FALSE(has_completed(&lts[3]), "Downgrade: waiter 3 waiting");

	/* Open a gap just wide enough for the [200..300] lock to be granted */
	T_ASSERT_POSIX_SUCCESS(posix_lock(a, 200, 100, 0), "Downgrade [200..300]");

	/*
	 * (We can't use LOCK_AND_CHECK here, because there may be two shared locks
	 *  with that range (our downgrade, plus waiter #1) - so ofd_get() could return
	 *  either one non-deterministically.)
	 */

	while (!has_completed(&lts[1])) {
		random_pause(); /* wait for waiter #1 to complete */
	}
	T_ASSERT_FALSE(has_completed(&lts[0]), "Downgrade: waiter 0 waiting");
	T_ASSERT_TRUE(has_completed(&lts[1]), "Downgrade: waiter 1 awoken");
	T_ASSERT_FALSE(has_completed(&lts[2]), "Downgrade: waiter 2 waiting");
	T_ASSERT_FALSE(has_completed(&lts[3]), "Downgrade: waiter 3 waiting");

	/* Open a gap just wide enough for the [400..600] lock to be granted */
	T_ASSERT_POSIX_SUCCESS(posix_lock(a, 400, 100, 0), "Downgrade [400..500]");

	while (!has_completed(&lts[2])) {
		random_pause(); /* wait for waiter #2 to complete */
	}
	T_ASSERT_FALSE(has_completed(&lts[0]), "Downgrade: waiter 0 waiting");
	T_ASSERT_TRUE(has_completed(&lts[2]), "Downgrade: waiter 2 awoken");
	T_ASSERT_FALSE(has_completed(&lts[3]), "Downgrade: waiter 3 waiting");

	/* Downgrade the remaining chunks */
	T_ASSERT_POSIX_SUCCESS(posix_lock(a, 0, 500, 0), "Downgrade [0..500]");

	while (!has_completed(&lts[0]) || !has_completed(&lts[3])) {
		random_pause(); /* wait for waiters #0 and #3 to complete */
	}
	T_ASSERT_TRUE(has_completed(&lts[0]), "Downgrade: waiter 0 awoken");
	T_ASSERT_TRUE(has_completed(&lts[3]), "Downgrade: waiter 3 awoken");

	/* Unlock the remaining OFD shared locks */
	UNLOCK_AND_CHECK("Downgrade: cleanup (unlock all shared OFD locks)", a,
	    0, 0, TYPE_OFD,
	    0, 0, 0, TYPE_POSIX,
	    0, 0, UNLOCK, -1);

	/* Unlock the remaining POSIX lock [0..500] */
	UNLOCK_AND_CHECK("Downgrade: cleanup (unlock all shared posix locks)", a,
	    0, 500, TYPE_POSIX,
	    0, 0, 0, TYPE_OFD,
	    0, 0, UNLOCK, -1);


	/* Test SEEK_END flock range decoding */

	{
		/* SEEK_END start=-10 len=10 */
		struct flock fl = {.l_start = -10, .l_len = 10, .l_type = F_WRLCK, .l_whence = SEEK_END};
		T_ASSERT_POSIX_SUCCESS(fcntl(a, F_SETLK, &fl), "SEEK_END: -10, 10");
		GET_CHECK("SEEK_END: -10, 10 ", a,
		    0, 0, EXCL, TYPE_OFD,
		    file_len - 10, 10, EXCL, pid);
	}

	{
		/* SEEK_END start=-10 len=10 */
		struct flock fl = {.l_start = -file_len, .l_len = file_len, .l_type = F_WRLCK, .l_whence = SEEK_END};
		T_ASSERT_POSIX_SUCCESS(fcntl(a, F_SETLK, &fl), "SEEK_END: -file_len, file_len");
		GET_CHECK("SEEK_END: -file_len, file_len", a,
		    0, 0, EXCL, TYPE_OFD,
		    0, file_len, EXCL, pid);
	}

	{
		/* Negative case: SEEK_END start=-(file_len + 10) len=20 */
		struct flock fl = {.l_start = -(file_len + 10), .l_len = 20, .l_type = F_WRLCK, .l_whence = SEEK_END};
		T_EXPECT_TRUE(fcntl(a, F_SETLK, &fl) && errno == EINVAL, "SEEK_END: -(file_len + 10), 20 => EINVAL");
	}

	T_ASSERT_POSIX_SUCCESS(posix_unlock(a, 0, 0), "SEEK_END: cleanup (release locks)");

	/* Test interactions between all 3 lock types */

	T_ASSERT_POSIX_SUCCESS(flock(a, LOCK_SH | LOCK_NB), "Interaction: flock(a, shared)");

	/* Take (waiting) exclusive locks in all 3 types on a_confined */
	start_lock_thread(TYPE_FLOCK, &lts[0], a_confined, 0, 0, EXCL | WAIT);
	start_lock_thread(TYPE_POSIX, &lts[1], a_confined, 0, 0, EXCL | WAIT);
	start_lock_thread(TYPE_OFD, &lts[2], a_confined, 0, 0, EXCL | WAIT);

	/* Yuck. Allow time for these threads to run -and- block on the flock lock */
	sleep(1);

	/* Take shared locks in the remaining 2 types (posix/ofd) on a */

	T_ASSERT_POSIX_SUCCESS(posix_lock(a, 0, 0, 0), "Interaction: posix_lock(a, 0, 0, 0)");
	T_ASSERT_POSIX_SUCCESS(ofd_lock(a, 0, 0, 0), "Interaction: ofd_lock(a, 0, 0, 0)");

	T_ASSERT_FALSE(has_completed(&lts[0]), "Interaction: flock-waiter is starting or waiting");
	T_ASSERT_FALSE(has_completed(&lts[1]), "Interaction: posix-waiter is starting or waiting");
	T_ASSERT_FALSE(has_completed(&lts[2]), "Interaction: ofd-waiter is starting or waiting");

	T_EXPECT_POSIX_FAILURE(flock(a, LOCK_EX | LOCK_NB), EAGAIN, "Interaction: can't flock-upgrade");
	T_EXPECT_POSIX_FAILURE(posix_lock(a, 0, 0, EXCL), EAGAIN, "Interaction: can't posix-upgrade");
	T_EXPECT_POSIX_FAILURE(ofd_lock(a, 0, 0, EXCL), EAGAIN, "Interaction: can't ofd-upgrade");

	/*
	 * At this point:
	 * - 'a' owns a shared flock && a shared OFD lock
	 * - this process owns a shared POSIX lock
	 * - three threads are (hopefully) blocked waiting to take exclusive locks
	 *   on 'a_confined.'
	 *
	 * Drop the POSIX lock ...
	 */
	T_ASSERT_POSIX_SUCCESS(posix_unlock(a, 0, 0), "Interaction: Unlock posix");

	random_pause(); /* wait a bit to see if there are consequences for the waiting locks */

	T_ASSERT_FALSE(has_completed(&lts[0]), "Interaction: flock-waiter is still starting or waiting");
	T_ASSERT_FALSE(has_completed(&lts[1]), "Interaction: posix-waiter is still starting or waiting");
	T_ASSERT_FALSE(has_completed(&lts[2]), "Interaction: ofd-waiter is still starting or waiting");

	/*
	 * and drop the flock lock ...
	 */
	T_ASSERT_POSIX_SUCCESS(flock(a, LOCK_UN), "Interaction: Unlock flock");

	random_pause(); /* wait a bit to see if there are consequences for the waiting locks */

	// Check that rdar://102160410 remains fixed.
	// Before that, the LOCK_UN above would release the OFD lock too

	T_ASSERT_FALSE(has_completed(&lts[0]), "Interaction: flock-waiter is still starting or waiting");
	T_ASSERT_FALSE(has_completed(&lts[1]), "Interaction: posix-waiter is still starting or waiting");
	T_ASSERT_FALSE(has_completed(&lts[2]), "Interaction: ofd-waiter is still starting or waiting");

	/*
	 * and finally drop the OFD lock, which should let one of the blocked threads
	 * acquire an exclusive lock. Work through them turn by turn.
	 */
	T_ASSERT_POSIX_SUCCESS(ofd_unlock(a, 0, 0), "Interaction: Unlock ofd");

	bool unlocked[3] = {
		false, false, false
	};

	for (uint32_t waiters = 3; waiters > 0; waiters--) {
		uint32_t num_waiting = 0;
		do {
			random_pause(); /* wait for consequences for the waiting locks */
			num_waiting = !has_completed(&lts[0]) + !has_completed(&lts[1]) + !has_completed(&lts[2]);
		} while (num_waiting == waiters);

		T_ASSERT_EQ(num_waiting, waiters - 1, "Interaction: 1 waiter awoke");

		if (has_completed(&lts[0]) && !unlocked[0]) {
			T_ASSERT_POSIX_SUCCESS(flock(a_confined, LOCK_UN), "Interaction: Flock awoke, unlocking");
			unlocked[0] = true;
		} else if (has_completed(&lts[1]) && !unlocked[1]) {
			T_ASSERT_POSIX_SUCCESS(posix_unlock(a_confined, 0, 0), "Interaction: posix awoke, unlocking");
			unlocked[1] = true;
		} else if (has_completed(&lts[2]) && !unlocked[2]) {
			T_ASSERT_POSIX_SUCCESS(ofd_unlock(a_confined, 0, 0), "Interaction: ofd awoke, unlocking");
			unlocked[2] = true;
		}
	}

	T_ASSERT_TRUE(has_completed(&lts[0]), "Interaction: flock-waiter has completed");
	T_ASSERT_TRUE(unlocked[0], "Interaction: flock-waiter was unlocked");

	T_ASSERT_TRUE(has_completed(&lts[1]), "Interaction: posix-waiter has completed");
	T_ASSERT_TRUE(unlocked[1], "Interaction: posix-waiter was unlocked");

	T_ASSERT_TRUE(has_completed(&lts[2]), "Interaction: ofd-waiter has completed");
	T_ASSERT_TRUE(unlocked[2], "Interaction: ofd-waiter was unlocked");
}
