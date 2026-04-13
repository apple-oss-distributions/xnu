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
	T_META_TIMEOUT(15),
	T_META_TAG_VM_PREFERRED,
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_ASROOT(true));

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
	pid_t pid;
	task_t task;
	volatile int should_exit;
} test_task_t;

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
wait_resume_child(shared_data_t *shared_data)
{
	pthread_mutex_lock(&shared_data->mutex);
	while (shared_data->flag != SUSPENDED) {
		/* wait until task_suspend is called */
		pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
	}
	shared_data->flag = RESUMED;
	OSMemoryBarrier();
	pthread_cond_signal(&shared_data->cond);
	pthread_mutex_unlock(&shared_data->mutex);
}

static void
mark_suspended(shared_data_t *shared_data)
{
	pthread_mutex_lock(&shared_data->mutex);
	T_QUIET; T_ASSERT_EQ(shared_data->flag, NOT_START, "task started already??");
	shared_data->flag = SUSPENDED;
	OSMemoryBarrier();
	pthread_cond_signal(&shared_data->cond);
	pthread_mutex_unlock(&shared_data->mutex);
}

static void
assert_resumed(shared_data_t *shared_data)
{
	pthread_mutex_lock(&shared_data->mutex);
	T_QUIET; T_ASSERT_NE(shared_data->flag, NOT_START, "task not started yet??");
	while (shared_data->flag == SUSPENDED) {
		/* wait until task is resumed */
		pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
	}
	T_QUIET; T_ASSERT_EQ(shared_data->flag, RESUMED, "task not resumed??");
	pthread_mutex_unlock(&shared_data->mutex);
}

static integer_t
get_suspend_count(task_t task)
{
	kern_return_t kr;
	task_basic_info_data_t basic_info;
	mach_msg_type_number_t bi_count = TASK_BASIC_INFO_COUNT;

	kr = task_info(task, TASK_BASIC_INFO,
	    (task_info_t)&basic_info, &bi_count);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "task_info");

	return basic_info.suspend_count;
}

static task_t
get_task_for_pid(pid_t pid)
{
	kern_return_t kr;
	task_t task = TASK_NULL;

	kr = task_for_pid(mach_task_self(), pid, &task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");
	T_ASSERT_NE(task, TASK_NULL, "task_for_pid task");

	return task;
}

T_DECL(task_suspend_and_resume,
    "calling legacy task_suspend and task_resume",
    T_META_TIMEOUT(15))
{
	kern_return_t kr;
	test_task_t target_task;
	shared_data_t *shared_data = NULL;
	pid_t child;

	/* Create shared data structure */
	shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	T_ASSERT_NE(shared_data, MAP_FAILED, "mmap");

	init_process_shared_data(shared_data);

	child = fork();
	T_ASSERT_NE(child, -1, "fork");

	if (child == 0) {
		/* Child process */
		wait_resume_child(shared_data);
		exit(0);
	}

	/* Parent process */
	target_task.pid = child;
	kr = task_for_pid(mach_task_self(), child, &target_task.task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");

	kr = task_suspend(target_task.task);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend");
	mark_suspended(shared_data);

	T_ASSERT_EQ(get_suspend_count(target_task.task), 1, "suspend_count == 1");

	kr = task_resume(target_task.task);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume");

	assert_resumed(shared_data);

	wait(NULL);
	cleanup_shared_data(shared_data);
	mach_port_deallocate(mach_task_self(), target_task.task);
	munmap(shared_data, sizeof(shared_data_t));
}

T_DECL(task_suspend2_and_resume2,
    "calling task_suspend2 and task_resume2",
    T_META_TIMEOUT(15))
{
	kern_return_t kr;
	test_task_t target_task;
	task_suspension_token_t token = TASK_NULL;
	shared_data_t *shared_data = NULL;
	pid_t child;

	/* Create shared data structure */
	shared_data = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	T_ASSERT_NE(shared_data, MAP_FAILED, "mmap");

	init_process_shared_data(shared_data);

	child = fork();
	T_ASSERT_NE(child, -1, "fork");

	if (child == 0) {
		/* Child process */
		wait_resume_child(shared_data);
		exit(0);
	}

	/* Parent process */
	target_task.pid = child;
	kr = task_for_pid(mach_task_self(), child, &target_task.task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");

	kr = task_suspend2(target_task.task, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
	T_ASSERT_NE(token, TASK_NULL, "task_suspend2 token");
	mark_suspended(shared_data);

	T_ASSERT_EQ(get_suspend_count(target_task.task), 1, "suspend_count == 1");

	kr = task_resume2(token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume2");

	assert_resumed(shared_data);

	wait(NULL);
	cleanup_shared_data(shared_data);
	mach_port_deallocate(mach_task_self(), target_task.task);
	munmap(shared_data, sizeof(shared_data_t));
}

T_DECL(task_suspend2_auto_resume,
    "task resume after the suspending process exited using task_suspend2",
    T_META_TIMEOUT(15))
{
	pid_t child0 = 0, child1 = 0;
	task_t target_task;
	task_suspension_token_t token = TASK_NULL;
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
		target_task = get_task_for_pid(child0);
		kr = task_suspend2(target_task, &token);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
		T_ASSERT_NE(token, TASK_NULL, "task_suspend2 token");
		T_ASSERT_EQ(get_suspend_count(target_task), 1, "suspend_count == 1");

		/* Signal we've called task_suspend2() */
		mark_suspended(shared_data);

		/* exit without resuming task */
		T_LOG("suspender exiting");
		exit(0);
	}

	/* This is child 0 */
	if (child0 == 0 && child1 == 0) {
		/* Wait until we are unsuspended by child1's exit */
		wait_resume_child(shared_data);

		T_LOG("suspended task exiting");
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

static void
loop_child(void)
{
	while (1) {
		usleep(SLEEP_INTERVAL);
	}
}

T_DECL(task_resume_incorrect_count,
    "calling legacy task_resume twice",
    T_META_TIMEOUT(15))
{
	kern_return_t kr;
	test_task_t target_task;
	pid_t child;

	child = fork();
	T_ASSERT_NE(child, -1, "fork");

	if (child == 0) {
		loop_child();
	}

	target_task.pid = child;
	kr = task_for_pid(mach_task_self(), child, &target_task.task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");

	kr = task_suspend(target_task.task);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend");

	kr = task_resume(target_task.task);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume");

	kr = task_resume(target_task.task);
	T_ASSERT_EQ(kr, KERN_FAILURE, "calling task_resume twice");

	kill(child, SIGKILL);
	wait(NULL);
	mach_port_deallocate(mach_task_self(), target_task.task);
}

T_DECL(task_resume2_incorrect_count,
    "calling task_resume2 twice",
    T_META_TIMEOUT(15))
{
	kern_return_t kr;
	test_task_t target_task;
	task_suspension_token_t token = TASK_NULL;
	pid_t child;

	child = fork();
	T_ASSERT_NE(child, -1, "fork");

	if (child == 0) {
		loop_child();
	}

	target_task.pid = child;
	kr = task_for_pid(mach_task_self(), child, &target_task.task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");

	kr = task_suspend2(target_task.task, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
	T_ASSERT_NE(token, TASK_NULL, "task_suspend2 token");

	kr = task_resume2(token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume2");

	kr = task_resume2(token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "calling task_resume2 twice");

	kill(child, SIGKILL);
	wait(NULL);
	mach_port_deallocate(mach_task_self(), target_task.task);
}

T_DECL(task_suspend2_multiple_token,
    "test calling task suspend2 multiple times",
    T_META_TIMEOUT(15))
{
	kern_return_t kr;
	test_task_t target_task;
	task_suspension_token_t token1 = TASK_NULL;
	task_suspension_token_t token2 = TASK_NULL;
	pid_t child;

	child = fork();
	T_ASSERT_NE(child, -1, "fork");

	if (child == 0) {
		loop_child();
	}

	target_task.pid = child;
	kr = task_for_pid(mach_task_self(), child, &target_task.task);
	T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");

	kr = task_suspend2(target_task.task, &token1);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
	T_ASSERT_NE(token1, TASK_NULL, "task_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_task.task), 1, "suspend_count == 1");

	kr = task_suspend2(target_task.task, &token2);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
	T_ASSERT_NE(token2, TASK_NULL, "task_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_task.task), 2, "suspend_count == 2");

	kr = task_resume2(token1);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume2");
	T_ASSERT_EQ(get_suspend_count(target_task.task), 1, "suspend_count == 1");

	kr = task_resume2(token2);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume2");
	T_ASSERT_EQ(get_suspend_count(target_task.task), 0, "suspend_count == 0");

	kill(child, SIGKILL);
	wait(NULL);
	mach_port_deallocate(mach_task_self(), target_task.task);
}

T_DECL(task_suspend_error_conditions,
    "test error conditions with invalid parameters",
    T_META_TIMEOUT(15))
{
	kern_return_t kr;
	task_suspension_token_t token = TASK_NULL;
	task_t invalid_task = (task_t)0xdeadbeef;
	task_suspension_token_t invalid_token = (task_suspension_token_t)0xdeadbeef;

	/* Note: calling task_suspend2() with NULL token will seg fault */

	/* Test invalid task handle */
	kr = task_suspend(invalid_task);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_suspend with invalid task");

	kr = task_resume(invalid_task);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_resume with invalid task");

	kr = task_suspend2(invalid_task, &token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_suspend2 with invalid task");

	kr = task_resume2(invalid_token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_resume2 with invalid token");

	/* Test TASK_NULL */
	kr = task_suspend(TASK_NULL);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_suspend with TASK_NULL");

	kr = task_resume(TASK_NULL);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_resume with TASK_NULL");

	kr = task_suspend2(TASK_NULL, &token);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_suspend2 with TASK_NULL");

	kr = task_resume2(TASK_NULL);
	T_ASSERT_EQ(kr, MACH_SEND_INVALID_DEST, "task_resume2 with TASK_NULL");
}

#define NUM_CONCURRENT_TASKS 5
typedef struct {
	task_t target_task;
	pthread_mutex_t *mutex;
	pthread_cond_t *cond;
	volatile int ready_count;
} concurrent_test_data_t;

static void *
concurrent_suspender(void *arg)
{
	kern_return_t kr;
	task_suspension_token_t token;
	concurrent_test_data_t *data = (concurrent_test_data_t *)arg;

	/* Signal we're ready and wait for all tasks */
	pthread_mutex_lock(data->mutex);
	data->ready_count++;
	while (data->ready_count < NUM_CONCURRENT_TASKS) {
		pthread_cond_wait(data->cond, data->mutex);
	}
	pthread_cond_broadcast(data->cond);
	pthread_mutex_unlock(data->mutex);

	/* All tasks suspend the target simultaneously */
	kr = task_suspend2(data->target_task, &token);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "concurrent task_suspend2");
	T_QUIET; T_ASSERT_NE(token, TASK_NULL, "concurrent token");

	/* Wait a bit to let all suspensions complete */
	usleep(SLEEP_INTERVAL);

	kr = task_resume2(token);
	T_QUIET; T_ASSERT_EQ(kr, KERN_SUCCESS, "concurrent task_resume2");

	return NULL;
}

T_DECL(task_suspend_concurrent,
    "test concurrent suspend/resume operations on same task",
    T_META_TIMEOUT(20))
{
	pthread_t suspender_tasks[NUM_CONCURRENT_TASKS];
	test_task_t target_task;
	concurrent_test_data_t data;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int ret;
	pid_t child;

	/* Initialize synchronization */
	ret = pthread_mutex_init(&mutex, NULL);
	T_ASSERT_EQ(ret, 0, "pthread_mutex_init");
	ret = pthread_cond_init(&cond, NULL);
	T_ASSERT_EQ(ret, 0, "pthread_cond_init");

	/* Create target task */
	child = fork();
	T_ASSERT_NE(child, -1, "fork");

	if (child == 0) {
		loop_child();
	}

	target_task.pid = child;
	ret = task_for_pid(mach_task_self(), child, &target_task.task);
	T_ASSERT_MACH_SUCCESS(ret, "task_for_pid");

	/* Initialize test data */
	data.target_task = target_task.task;
	data.mutex = &mutex;
	data.cond = &cond;
	data.ready_count = 0;

	/* Create suspender tasks */
	for (int i = 0; i < NUM_CONCURRENT_TASKS; i++) {
		ret = pthread_create(&suspender_tasks[i], NULL, concurrent_suspender, &data);
		T_ASSERT_EQ(ret, 0, "pthread_create suspender");
	}

	/* Wait for all suspender tasks to complete */
	for (int i = 0; i < NUM_CONCURRENT_TASKS; i++) {
		pthread_join(suspender_tasks[i], NULL);
	}

	/* Verify target task is not suspended */
	T_ASSERT_EQ(get_suspend_count(target_task.task), 0, "final suspend_count == 0");

	pthread_mutex_destroy(&mutex);
	pthread_cond_destroy(&cond);
	kill(child, SIGKILL);
	wait(NULL);
	mach_port_deallocate(mach_task_self(), target_task.task);
}

T_DECL(task_suspend_mixed_api_no_sender,
    "test no-sender notification doesn't affect legacy suspensions",
    T_META_TIMEOUT(20))
{
	pid_t child0 = 0, child1 = 0;
	task_t target_task;
	task_suspension_token_t token = TASK_NULL;
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

	/* This is child1 - uses task_suspend2 and exits */
	if (child0 != 0 && child1 == 0) {
		target_task = get_task_for_pid(child0);

		/* Suspend with task_suspend2 */
		kr = task_suspend2(target_task, &token);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
		T_ASSERT_NE(token, TASK_NULL, "task_suspend2 token");

		/* Wait for parent to also suspend (parent will mark_suspended) */
		pthread_mutex_lock(&shared_data->mutex);
		while (shared_data->flag != SUSPENDED) {
			pthread_cond_wait(&shared_data->cond, &shared_data->mutex);
		}
		pthread_mutex_unlock(&shared_data->mutex);

		T_ASSERT_EQ(get_suspend_count(target_task), 2, "suspend_count == 2");

		/* Exit without resuming - should trigger no-sender notification */
		T_LOG("task_suspend2 process exiting");
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
	target_task = get_task_for_pid(child0);
	kr = task_suspend(target_task);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend legacy");

	/* Signal child1 that we've also suspended */
	mark_suspended(shared_data);

	/* Wait for child1 to exit - this should auto-resume the task_suspend2 suspension */
	wait(NULL);
	usleep(SLEEP_INTERVAL); /* Give time for no-sender notification to process */

	/* Verify that legacy suspension is still active despite no-sender notification */
	T_ASSERT_EQ(get_suspend_count(target_task), 1, "legacy suspension should remain");

	/* Resume the legacy suspension */
	kr = task_resume(target_task);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_resume legacy");
	T_ASSERT_EQ(get_suspend_count(target_task), 0, "suspend_count == 0");

	/* Kill child0 since it's now running */
	kill(child0, SIGKILL);
	wait(NULL);

	/* Clean up */
	cleanup_shared_data(shared_data);
	munmap(shared_data, sizeof(shared_data_t));
}

#define TASK_EXITING_OR_EXITED(kr) \
	((kr) == KERN_INVALID_ARGUMENT || \
	 (kr) == MACH_SEND_INVALID_DEST || \
	 (kr) == MIG_SERVER_DIED)

T_DECL(task_suspend_sigkill_target,
    "test SIGKILL on suspended process",
    T_META_TIMEOUT(20))
{
	pid_t child = 0;
	task_t target_task;
	task_suspension_token_t token = TASK_NULL;
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

	/* This is child - target process */
	if (child == 0) {
		/* Signal that we're running */
		pthread_mutex_lock(&shared_data->mutex);
		shared_data->flag = RUNNING;
		pthread_cond_signal(&shared_data->cond);
		pthread_mutex_unlock(&shared_data->mutex);

		/* Main task loops indefinitely */
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

	target_task = get_task_for_pid(child);

	/* Suspend the main task */
	kr = task_suspend2(target_task, &token);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "task_suspend2");
	T_ASSERT_NE(token, TASK_NULL, "task_suspend2 token");
	T_ASSERT_EQ(get_suspend_count(target_task), 1, "suspend_count == 1");

	/* Kill the suspended process */
	kill(child, SIGKILL);

	/* Wait for child to die */
	pid_t waited = waitpid(child, &status, 0);
	T_ASSERT_EQ(waited, child, "waitpid");
	T_ASSERT_TRUE(WIFSIGNALED(status), "child was signaled");
	T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "child killed by SIGKILL");

	/* Try to resume the dead process - should fail */
	kr = task_resume2(token);
	T_LOG("task_resume2 returned %d", kr);
	T_ASSERT_TRUE(TASK_EXITING_OR_EXITED(kr), "resume2 on dead process should fail");

	/* Clean up */
	cleanup_shared_data(shared_data);
	munmap(shared_data, sizeof(shared_data_t));
}

T_DECL(task_suspend_stale_handle,
    "test suspending tasks with stale handles after process death",
    T_META_TIMEOUT(15))
{
	int status;
	pid_t child = 0;
	kern_return_t kr;
	task_t target_task;
	task_suspension_token_t token = TASK_NULL;

	child = fork();
	T_ASSERT_NE(child, -1, "fork child");

	/* This is child - loop indefinitely until killed */
	if (child == 0) {
		while (1) {
			usleep(SLEEP_INTERVAL);
		}
	}

	/* Get task handle while child is alive */
	target_task = get_task_for_pid(child);
	T_ASSERT_NE(target_task, TASK_NULL, "get_task_for_pid");

	/* Kill the child process */
	kill(child, SIGKILL);
	pid_t waited = waitpid(child, &status, 0);
	T_ASSERT_EQ(waited, child, "waitpid");
	T_ASSERT_TRUE(WIFSIGNALED(status), "child was signaled");
	T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "child killed by SIGKILL");

	/* Now try to suspend using the stale task handle */
	kr = task_suspend(target_task);
	T_LOG("task_suspend returned %d", kr);
	T_ASSERT_TRUE(TASK_EXITING_OR_EXITED(kr), "task_suspend on dead process should fail");

	kr = task_suspend2(target_task, &token);
	T_LOG("task_suspend2 returned %d", kr);
	T_ASSERT_TRUE(TASK_EXITING_OR_EXITED(kr), "task_suspend2 on dead process should fail");

	kr = task_resume(target_task);
	T_LOG("task_resume returned %d", kr);
	T_ASSERT_TRUE(TASK_EXITING_OR_EXITED(kr), "task_resume on dead process should fail");
}
