#include <darwintest.h>

#include <stdlib.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <libkern/OSAtomic.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_OWNER("skwok2"),
	T_META_TIMEOUT(10),
	T_META_TAG_VM_PREFERRED,
	T_META_RUN_CONCURRENTLY(TRUE));

#define NOT_START 0
#define SUSPENDED 1
#define RESUMED 2
#define RUNNING 3
#define SLEEP_INTERVAL 1000

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int flag;
} shared_data_t;

typedef struct {
	pthread_t pthread;
	thread_t thread;
	volatile int should_exit;
} test_thread_t;

static void
init_shared_data(shared_data_t *shared_data)
{
	int ret;
	ret = pthread_mutex_init(&shared_data->mutex, NULL);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_mutex_init");
	ret = pthread_cond_init(&shared_data->cond, NULL);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_cond_init");
	shared_data->flag = NOT_START;
}

static void
cleanup_shared_data(shared_data_t *shared_data)
{
	pthread_mutex_destroy(&shared_data->mutex);
	pthread_cond_destroy(&shared_data->cond);
}

static void
init_process_shared_data(shared_data_t *shared_data)
{
	int ret;
	pthread_mutexattr_t mattr;
	pthread_condattr_t cattr;

	/* Initialize mutex */
	ret = pthread_mutexattr_init(&mattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_mutexattr_init");
	ret = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_mutexattr_setpshared");
	ret = pthread_mutex_init(&shared_data->mutex, &mattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_mutex_init");
	pthread_mutexattr_destroy(&mattr);

	/* Initialize condition variable */
	ret = pthread_condattr_init(&cattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_condattr_init");
	ret = pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_condattr_setpshared");
	ret = pthread_cond_init(&shared_data->cond, &cattr);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_cond_init");
	pthread_condattr_destroy(&cattr);

	shared_data->flag = NOT_START;
}

static void
create_test_thread(
	test_thread_t *test_thread,
	void *(*func)(void*),
	void *arg)
{
	int ret;

	test_thread->should_exit = 0;
	ret = pthread_create(&test_thread->pthread, NULL, func, arg);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_create");
	T_QUIET; T_ASSERT_NE(test_thread->pthread, NULL, "pthread_create");

	test_thread->thread = pthread_mach_thread_np(test_thread->pthread);
	T_QUIET; T_ASSERT_NE(test_thread->thread, 0, "pthread_mach_thread_np");
}

static void
cleanup_test_thread(test_thread_t *test_thread)
{
	int ret;
	test_thread->should_exit = 1;
	ret = pthread_join(test_thread->pthread, NULL);
	T_QUIET; T_ASSERT_EQ(ret, 0, "pthread_join");
}

static void *
wait_resume(void *arg)
{
	shared_data_t *shared_data = (shared_data_t *)arg;

	pthread_mutex_lock(&shared_data->mutex);
	while (shared_data->flag != SUSPENDED) {
		/* wait until thread_suspend is called */
		pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
	}
	shared_data->flag = RESUMED;
	OSMemoryBarrier();
	pthread_cond_signal(&shared_data->cond);
	pthread_mutex_unlock(&shared_data->mutex);

	return NULL;
}

static void
mark_suspended(shared_data_t *shared_data)
{
	pthread_mutex_lock(&shared_data->mutex);
	T_QUIET; T_ASSERT_EQ(shared_data->flag, NOT_START, "thread started already??");
	shared_data->flag = SUSPENDED;
	OSMemoryBarrier();
	pthread_cond_signal(&shared_data->cond);
	pthread_mutex_unlock(&shared_data->mutex);
}

static void
assert_resumed(shared_data_t *shared_data)
{
	pthread_mutex_lock(&shared_data->mutex);
	T_QUIET; T_ASSERT_NE(shared_data->flag, NOT_START, "thread not started yet??");
	while (shared_data->flag == SUSPENDED) {
		/* wait until thread is resumed */
		pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
	}
	T_QUIET; T_ASSERT_EQ(shared_data->flag, RESUMED, "thread not resumed??");
	pthread_mutex_unlock(&shared_data->mutex);
}

static integer_t
get_suspend_count(thread_t thread)
{
	kern_return_t kr;
	thread_basic_info_data_t basic_info;
	mach_msg_type_number_t bi_count = THREAD_BASIC_INFO_COUNT;

	kr = thread_info(thread, THREAD_BASIC_INFO,
	    (thread_info_t)&basic_info, &bi_count);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_info");

	return basic_info.suspend_count;
}

static thread_t
get_thread_for_pid(pid_t pid)
{
	kern_return_t kr;
	task_t task = TASK_NULL;
	thread_act_array_t threads = NULL;
	mach_msg_type_number_t thread_count = 0;

	kr = task_for_pid(mach_task_self(), pid, &task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");
	T_ASSERT_NE(task, TASK_NULL, "task_for_pid task");

	kr = task_threads(task, &threads, &thread_count);
	T_ASSERT_MACH_SUCCESS(kr, "task_threads");
	T_ASSERT_NE(threads, NULL, "task_threads threads");

	T_ASSERT_NE(threads[0], THREAD_NULL, "threads[0]");

	return threads[0];
}

T_DECL(thread_suspend_and_resume,
    "calling legacy thread_suspend and thread_resume",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;
	shared_data_t shared_data;

	init_shared_data(&shared_data);
	create_test_thread(&target_thread, wait_resume, (void *)&shared_data);

	kr = thread_suspend(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend");
	mark_suspended(&shared_data);

	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume");

	assert_resumed(&shared_data);

	cleanup_test_thread(&target_thread);
	cleanup_shared_data(&shared_data);
}

T_DECL(thread_suspend2_and_resume2,
    "calling thread_suspend2 and thread_resume2",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;
	shared_data_t shared_data;

	init_shared_data(&shared_data);
	create_test_thread(&target_thread, wait_resume, (void *)&shared_data);

	kr = thread_suspend2(target_thread.thread, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");
	mark_suspended(&shared_data);

	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume2(token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume");

	assert_resumed(&shared_data);

	cleanup_test_thread(&target_thread);
	cleanup_shared_data(&shared_data);
}

T_DECL(thread_suspend2_auto_resume,
    "thread resume after the suspending process exited using thread_suspend2",
    T_META_TIMEOUT(10),
    T_META_ASROOT(true))
{
	pid_t child0 = 0, child1 = 0;
	thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;
	kern_return_t kr;
	shared_data_t *shared_data = NULL;

	/* Create shared data structure */
	shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	T_ASSERT_NE(shared_data, MAP_FAILED, "mmap");

	init_process_shared_data(shared_data);

	child0 = fork();
	T_ASSERT_NE(child0, -1, "fork child0");

	if (child0) {
		child1 = fork();
		T_ASSERT_NE(child1, -1, "fork child1");
	}

	/* This is child1 */
	if (child0 != 0 && child1 == 0) {
		/* suspend child0 */
		target_thread = get_thread_for_pid(child0);
		kr = thread_suspend2(target_thread, &token);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
		T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");
		T_ASSERT_EQ(get_suspend_count(target_thread), 1, "suspend_count == 1");

		/* Signal we've called thread_suspend2() */
		mark_suspended(shared_data);

		/* exit without resuming thread */
		T_LOG("suspender exiting");
		exit(0);
	}

	/* This is child 0 */
	if (child0 == 0 && child1 == 0) {
		/* Wait until we are unsuspended by child1's exit */
		wait_resume((void *)shared_data);

		T_LOG("suspended thread exiting");
		exit(0);
	}

	/* This is parent, wait for both children */
	wait(NULL);
	wait(NULL);

	assert_resumed(shared_data);

	/* Clean up */
	cleanup_shared_data(shared_data);
	munmap(shared_data, sizeof(shared_data_t));
}

static void *
loop(void *arg)
{
	test_thread_t *test_thread = (test_thread_t *)arg;
	while (!test_thread->should_exit) {
		usleep(SLEEP_INTERVAL);
	}
	return NULL;
}

T_DECL(thread_resume_incorrect_count,
    "calling legacy thread_resume twice",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;

	create_test_thread(&target_thread, loop, (void *)&target_thread);

	kr = thread_suspend(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend");

	kr = thread_resume(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume");

	kr = thread_resume(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_FAILURE, "calling thread_resume twice");

	cleanup_test_thread(&target_thread);
}

T_DECL(thread_resume2_incorrect_count,
    "calling thread_resume2 twice",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;

	create_test_thread(&target_thread, loop, (void *)&target_thread);

	kr = thread_suspend2(target_thread.thread, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");

	kr = thread_resume2(token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume2");

	kr = thread_resume2(token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "calling thread_resume2 twice");

	cleanup_test_thread(&target_thread);
}

/*
 * Note: It is impossible to mix thread_suspend() and thread_resume2()
 * as the new resume api takes a suspension token.
 */
T_DECL(thread_suspend_mix_interface,
    "test mixing thread_suspend2 and the legacy thread_resume api",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;

	create_test_thread(&target_thread, loop, (void *)&target_thread);

	kr = thread_suspend2(target_thread.thread, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_FAILURE,
	    "calling thread_resume() on a thread suspended by thread_suspend2 should fail");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume2(token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume2");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 0, "suspend_count == 0");

	cleanup_test_thread(&target_thread);
}

T_DECL(thread_suspend_mix_refcount,
    "test suspension refcount with suspend and suspend2 are used together",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;

	create_test_thread(&target_thread, loop, (void *)&target_thread);

	kr = thread_suspend2(target_thread.thread, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_suspend(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 2, "suspend_count == 2");

	kr = thread_resume(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume(target_thread.thread);
	T_ASSERT_EQ(kr, KERN_FAILURE, "excess legacy resume should fail");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume2(token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume2");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 0, "suspend_count == 0");

	kr = thread_resume2(token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "excess resume2 should fail");

	cleanup_test_thread(&target_thread);
}

T_DECL(thread_suspend2_multiple_token,
    "test calling thread suspend2 multiple times",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	test_thread_t target_thread;
	thread_suspension_token_t token1 = THREAD_NULL;
	thread_suspension_token_t token2 = THREAD_NULL;

	create_test_thread(&target_thread, loop, (void *)&target_thread);

	kr = thread_suspend2(target_thread.thread, &token1);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token1, THREAD_NULL, "thread_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_suspend2(target_thread.thread, &token2);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token2, THREAD_NULL, "thread_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 2, "suspend_count == 2");

	kr = thread_resume2(token1);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 1, "suspend_count == 1");

	kr = thread_resume2(token2);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume2");
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 0, "suspend_count == 0");

	cleanup_test_thread(&target_thread);
}

T_DECL(thread_suspend_error_conditions,
    "test error conditions with invalid parameters",
    T_META_TIMEOUT(10))
{
	kern_return_t kr;
	thread_suspension_token_t token = THREAD_NULL;
	thread_t invalid_thread = (thread_t)0xdeadbeef;
	thread_suspension_token_t invalid_token = (thread_suspension_token_t)0xdeadbeef;

	/* Note: calling thread_suspend2() will NULL token will seg fault */

	/* Test invalid thread handle */
	kr = thread_suspend(invalid_thread);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_suspend with invalid thread");

	kr = thread_resume(invalid_thread);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_resume with invalid thread");

	kr = thread_suspend2(invalid_thread, &token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_suspend2 with invalid thread");

	kr = thread_resume2(invalid_token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_resume2 with invalid token");

	/* Test THREAD_NULL */
	kr = thread_suspend(THREAD_NULL);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_suspend with THREAD_NULL");

	kr = thread_resume(THREAD_NULL);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_resume with THREAD_NULL");

	kr = thread_suspend2(THREAD_NULL, &token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_suspen2 with THREAD_NULL");

	kr = thread_resume2(THREAD_NULL);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "thread_resume2 with THREAD_NULL");
}

#define NUM_CONCURRENT_THREADS 5
typedef struct {
	thread_t target_thread;
	pthread_mutex_t *mutex;
	pthread_cond_t *cond;
	volatile int ready_count;
} concurrent_test_data_t;

static void *
concurrent_suspender(void *arg)
{
	kern_return_t kr;
	thread_suspension_token_t token;
	concurrent_test_data_t *data = (concurrent_test_data_t *)arg;

	/* Signal we're ready and wait for all threads */
	pthread_mutex_lock(data->mutex);
	data->ready_count++;
	while (data->ready_count < NUM_CONCURRENT_THREADS) {
		pthread_cond_wait(data->cond, data->mutex);
	}
	pthread_cond_broadcast(data->cond);
	pthread_mutex_unlock(data->mutex);

	/* All threads suspend the target simultaneously */
	kr = thread_suspend2(data->target_thread, &token);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "concurrent thread_suspend2");
	T_QUIET; T_ASSERT_NE(token, THREAD_NULL, "concurrent token");

	/* Wait a bit to let all suspensions complete */
	usleep(SLEEP_INTERVAL);

	/* Resume in reverse order */
	kr = thread_resume2(token);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "concurrent thread_resume2");

	return NULL;
}

T_DECL(thread_suspend_concurrent,
    "test concurrent suspend/resume operations on same thread",
    T_META_TIMEOUT(15))
{
	pthread_t suspender_threads[NUM_CONCURRENT_THREADS];
	test_thread_t target_thread;
	concurrent_test_data_t data;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int ret;

	/* Initialize synchronization */
	ret = pthread_mutex_init(&mutex, NULL);
	T_ASSERT_EQ(ret, 0, "pthread_mutex_init");
	ret = pthread_cond_init(&cond, NULL);
	T_ASSERT_EQ(ret, 0, "pthread_cond_init");

	/* Create target thread */
	create_test_thread(&target_thread, loop, (void *)&target_thread);

	/* Initialize test data */
	data.target_thread = target_thread.thread;
	data.mutex = &mutex;
	data.cond = &cond;
	data.ready_count = 0;

	/* Create suspender threads */
	for (int i = 0; i < NUM_CONCURRENT_THREADS; i++) {
		ret = pthread_create(&suspender_threads[i], NULL, concurrent_suspender, &data);
		T_ASSERT_EQ(ret, 0, "pthread_create suspender");
	}

	/* Wait for all suspender threads to complete */
	for (int i = 0; i < NUM_CONCURRENT_THREADS; i++) {
		pthread_join(suspender_threads[i], NULL);
	}

	/* Verify target thread is not suspended */
	T_ASSERT_EQ(get_suspend_count(target_thread.thread), 0, "final suspend_count == 0");

	pthread_mutex_destroy(&mutex);
	pthread_cond_destroy(&cond);
	cleanup_test_thread(&target_thread);
}

T_DECL(thread_suspend_mixed_api_no_sender,
    "test no-sender notification doesn't affect legacy suspensions",
    T_META_TIMEOUT(15),
    T_META_ASROOT(true))
{
	pid_t child0 = 0, child1 = 0;
	thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;
	kern_return_t kr;
	shared_data_t *shared_data = NULL;

	/* Create shared data structure */
	shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	T_ASSERT_NE(shared_data, MAP_FAILED, "mmap");

	init_process_shared_data(shared_data);

	child0 = fork();
	T_ASSERT_NE(child0, -1, "fork child0");

	if (child0) {
		child1 = fork();
		T_ASSERT_NE(child1, -1, "fork child1");
	}

	/* This is child1 - uses thread_suspend2 and exits */
	if (child0 != 0 && child1 == 0) {
		target_thread = get_thread_for_pid(child0);

		/* Suspend with thread_suspend2 */
		kr = thread_suspend2(target_thread, &token);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
		T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");

		/* Wait for parent to also suspend (parent will mark_suspended) */
		pthread_mutex_lock(&shared_data->mutex);
		while (shared_data->flag != SUSPENDED) {
			pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
		}
		pthread_mutex_unlock(&shared_data->mutex);

		T_ASSERT_EQ(get_suspend_count(target_thread), 2, "suspend_count == 2");

		/* Exit without resuming - should trigger no-sender notification */
		T_LOG("thread_suspend2 process exiting");
		exit(0);
	}

	/* This is child0 - target process */
	if (child0 == 0 && child1 == 0) {
		/* Wait indefinitely - parent will check our state and resume us */
		while (1) {
			usleep(SLEEP_INTERVAL);
		}
	}

	/* This is parent */
	/* Now also suspend with legacy API */
	target_thread = get_thread_for_pid(child0);
	kr = thread_suspend(target_thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend legacy");

	/* Signal child1 that we've also suspended */
	mark_suspended(shared_data);

	/* Wait for child1 to exit - this should auto-resume the thread_suspend2 suspension */
	wait(NULL);
	usleep(SLEEP_INTERVAL); /* Give time for no-sender notification to process */

	/* Verify that legacy suspension is still active despite no-sender notification */
	T_ASSERT_EQ(get_suspend_count(target_thread), 1, "legacy suspension should remain");

	/* Resume the legacy suspension */
	kr = thread_resume(target_thread);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_resume legacy");
	T_ASSERT_EQ(get_suspend_count(target_thread), 0, "suspend_count == 0");

	/* Kill child0 since it's now running */
	kill(child0, SIGKILL);
	wait(NULL);

	/* Clean up */
	cleanup_shared_data(shared_data);
	munmap(shared_data, sizeof(shared_data_t));
}

T_DECL(thread_suspend_sigkill_target,
    "test SIGKILL on suspended process",
    T_META_TIMEOUT(15),
    T_META_ASROOT(true))
{
	pid_t child = 0;
	thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;
	kern_return_t kr;
	int status;
	shared_data_t *shared_data = NULL;

	/* Create shared data structure */
	shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	T_ASSERT_NE(shared_data, MAP_FAILED, "mmap");

	init_process_shared_data(shared_data);

	child = fork();
	T_ASSERT_NE(child, -1, "fork child");

	/* This is child - target process with multiple threads */
	if (child == 0) {
		test_thread_t target_thread;

		create_test_thread(&target_thread, loop, (void *)&target_thread);

		/* Signal that we're running */
		pthread_mutex_lock(&shared_data->mutex);
		shared_data->flag = RUNNING;
		pthread_cond_signal(&shared_data->cond);
		pthread_mutex_unlock(&shared_data->mutex);

		/* Main thread loops indefinitely */
		while (1) {
			usleep(SLEEP_INTERVAL);
		}
	}

	/* This is parent */
	/* Wait for child to signal it's running */
	pthread_mutex_lock(&shared_data->mutex);
	while (shared_data->flag != RUNNING) {
		pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
	}
	pthread_mutex_unlock(&shared_data->mutex);

	target_thread = get_thread_for_pid(child);

	/* Suspend the main thread */
	kr = thread_suspend2(target_thread, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "thread_suspend2");
	T_ASSERT_NE(token, THREAD_NULL, "thread_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_thread), 1, "suspend_count == 1");

	/* Kill the suspended process */
	kill(child, SIGKILL);

	/* Wait for child to die */
	pid_t waited = waitpid(child, &status, 0);
	T_ASSERT_EQ(waited, child, "waitpid");
	T_ASSERT_TRUE(WIFSIGNALED(status), "child was signaled");
	T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "child killed by SIGKILL");

	/*
	 * Now try to resume using the stale thread handle.
	 * Note that return value depends on state of the clean up.
	 * Some possible values are KERN_INVALID_ARGUMENT and
	 * MACH_SEND_INVALID_DEST.
	 */
	kr = thread_resume2(token);
	T_ASSERT_NE(kr, KERN_SUCCESS, "thread_resume on dead process should fail");

	/* Clean up */
	cleanup_shared_data(shared_data);
	munmap(shared_data, sizeof(shared_data_t));
}

T_DECL(thread_suspend_stale_handle,
    "test suspending threads with stale handles after process death",
    T_META_TIMEOUT(15),
    T_META_ASROOT(true))
{
	int status;
	pid_t child = 0;
	kern_return_t kr;
	thread_t target_thread;
	thread_suspension_token_t token = THREAD_NULL;

	child = fork();
	T_ASSERT_NE(child, -1, "fork child");

	/* This is child - loop indefinitely until killed */
	if (child == 0) {
		while (1) {
			usleep(SLEEP_INTERVAL);
		}
	}

	/* Get thread handle while child is alive */
	target_thread = get_thread_for_pid(child);
	T_ASSERT_NE(target_thread, THREAD_NULL, "get_thread_for_pid");

	/* Kill the child process */
	kill(child, SIGKILL);
	pid_t waited = waitpid(child, &status, 0);
	T_ASSERT_EQ(waited, child, "waitpid");
	T_ASSERT_TRUE(WIFSIGNALED(status), "child was signaled");
	T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "child killed by SIGKILL");

	/*
	 * Now try to suspend using the stale thread handle.
	 * Note that return value depends on state of the clean up.
	 * Some possible values are KERN_INVALID_ARGUMENT and
	 * MACH_SEND_INVALID_DEST.
	 */
	kr = thread_suspend(target_thread);
	T_ASSERT_NE(kr, KERN_SUCCESS, "thread_suspend on dead process should fail");

	kr = thread_suspend2(target_thread, &token);
	T_ASSERT_NE(kr, KERN_SUCCESS, "thread_suspend2 on dead process should fail");

	kr = thread_resume(target_thread);
	T_ASSERT_NE(kr, KERN_SUCCESS, "thread_resume on dead process should fail");
}
