#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/qos.h>

#include <dispatch/dispatch.h>
#include <os/lock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

#include <pthread/workqueue_private.h>
#include <pthread/qos_private.h>

static dispatch_group_t group;
static mach_timebase_info_data_t timebase_info;

static void
req_cooperative_wq_threads(qos_class_t qos, size_t num_threads)
{
	int ret;

	for (size_t i = 0; i < num_threads; i++) {
		dispatch_group_enter(group);

		ret = _pthread_workqueue_add_cooperativethreads(1,
		    _pthread_qos_class_encode(qos, 0, 0));
		assert(ret == 0);
	}
}

static void
req_wq_threads(qos_class_t qos, size_t num_threads, bool overcommit)
{
	int ret;

	for (size_t i = 0; i < num_threads; i++) {
		dispatch_group_enter(group);

		ret = _pthread_workqueue_addthreads(1,
		    _pthread_qos_class_encode(qos, 0,
		    (overcommit ? _PTHREAD_PRIORITY_OVERCOMMIT_FLAG : 0)));
		assert(ret == 0);
	}
}

static uint32_t
ncpus(void)
{
	static uint32_t num_cpus;
	if (!num_cpus) {
		uint32_t n;
		size_t s = sizeof(n);
		sysctlbyname("hw.ncpu", &n, &s, NULL, 0);
		num_cpus = n;
	}
	return num_cpus;
}

static inline bool
thread_is_overcommit(pthread_priority_t priority)
{
	return (priority & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) != 0;
}

static inline bool
thread_is_nonovercommit(pthread_priority_t priority)
{
	return (priority & (_PTHREAD_PRIORITY_OVERCOMMIT_FLAG | _PTHREAD_PRIORITY_COOPERATIVE_FLAG)) != 0;
}

static inline bool
thread_is_cooperative(pthread_priority_t priority)
{
	return (priority & _PTHREAD_PRIORITY_COOPERATIVE_FLAG) != 0;
}

qos_class_t
thread_has_qos(pthread_priority_t pri)
{
	return _pthread_qos_class_decode(pri, NULL, NULL);
}

char *
qos_to_str(qos_class_t qos)
{
	switch (qos) {
	case QOS_CLASS_MAINTENANCE:
		return "MT";
	case QOS_CLASS_BACKGROUND:
		return "BG";
	case QOS_CLASS_UTILITY:
		return "UT";
	case QOS_CLASS_DEFAULT:
		return "DEF";
	case QOS_CLASS_USER_INITIATED:
		return "IN";
	case QOS_CLASS_USER_INTERACTIVE:
		return "UI";
	}
}

/*
 * Test that we handle cooperative requests first and then overcommit if they
 * are at the same QoS
 */

static bool overcommit_thread_request_handled = false;
static bool cooperative_thread_request_handled = false;

static void
worker_cooperative_then_overcommit(pthread_priority_t priority)
{
	if (thread_is_cooperative(priority)) {
		assert(!overcommit_thread_request_handled);
		cooperative_thread_request_handled = true;
	} else if (thread_is_overcommit(priority)) {
		assert(cooperative_thread_request_handled);
		overcommit_thread_request_handled = true;
	}

	dispatch_group_leave(group);
}

int
do_cooperative_then_overcommit()
{
	int ret = _pthread_workqueue_init(worker_cooperative_then_overcommit, 0, 0);
	assert(ret == 0);

	req_wq_threads(QOS_CLASS_USER_INITIATED, 1, true);
	req_cooperative_wq_threads(QOS_CLASS_USER_INITIATED, 1);

	dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
	return 0;
}

/*
 * Test thread reuse from cooperative requests
 */

bool test_should_end = false;

qos_class_t
get_rand_qos_class(void)
{
	switch (rand() % 6) {
	case 0:
		return QOS_CLASS_MAINTENANCE;
	case 1:
		return QOS_CLASS_BACKGROUND;
	case 2:
		return QOS_CLASS_UTILITY;
	case 3:
		return QOS_CLASS_DEFAULT;
	case 4:
		return QOS_CLASS_USER_INITIATED;
	case 5:
		return QOS_CLASS_USER_INTERACTIVE;
	}
}

int
get_rand_num_thread_requests(void)
{
	return rand() % (ncpus() * 2);
}

uint64_t
get_rand_spin_duration_nsecs(void)
{
	/* Spin for at most half a second */
	return rand() % (NSEC_PER_SEC / 2);
}

void
spin(uint64_t spin_duration_nsecs)
{
	uint64_t duration = spin_duration_nsecs * timebase_info.denom / timebase_info.numer;
	uint64_t deadline = mach_absolute_time() + duration;
	while (mach_absolute_time() < deadline) {
		;
	}
}

static void
worker_cb_stress(pthread_priority_t priority)
{
	if (test_should_end) {
		dispatch_group_leave(group);
		return;
	}

	if (thread_is_cooperative(priority)) {
		printf("\t Cooperative thread of QoS %s\n", qos_to_str(thread_has_qos(priority)));
		spin(get_rand_spin_duration_nsecs());
		req_wq_threads(get_rand_qos_class(), get_rand_num_thread_requests(), false);
	} else if (thread_is_nonovercommit(priority)) {
		printf("\t Nonovercommit thread of QoS %s\n", qos_to_str(thread_has_qos(priority)));

		spin(get_rand_spin_duration_nsecs());
		req_cooperative_wq_threads(get_rand_qos_class(), get_rand_num_thread_requests());
	} else {
		printf("\t Overcommit thread of QoS %s\n", qos_to_str(thread_has_qos(priority)));
		req_wq_threads(get_rand_qos_class(), get_rand_num_thread_requests(), true);
		spin(get_rand_spin_duration_nsecs());
	}

	dispatch_group_leave(group);
}

int
do_stress_test()
{
	int ret = _pthread_workqueue_init(worker_cb_stress, 0, 0);
	assert(ret == 0);

	req_wq_threads(QOS_CLASS_DEFAULT, ncpus() / 2, true);
	req_cooperative_wq_threads(QOS_CLASS_USER_INITIATED, ncpus());
	req_wq_threads(QOS_CLASS_DEFAULT, ncpus(), false);

	sleep(10);

	test_should_end = true;

	dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
	printf("\n All thread requests completed\n");
	return 0;
}

int
main(int argc, char * argv[])
{
	int ret = 0;

	if (argc < 2) {
		return EINVAL;
	}

	const char *cmd = argv[1];

	group = dispatch_group_create();
	mach_timebase_info(&timebase_info);

	if (strcmp(cmd, "cooperative_then_overcommit") == 0) {
		return do_cooperative_then_overcommit();
	}

	if (strcmp(cmd, "stress_test") == 0) {
		return do_stress_test();
	}

	return -1;
}
