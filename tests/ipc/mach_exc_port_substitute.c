#include <unistd.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(TRUE));

int cur_test;
mach_port_t child_read;

extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

extern kern_return_t
catch_mach_exception_raise(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count);

extern kern_return_t
catch_mach_exception_raise_state(
	mach_port_t exception_port,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count);

extern kern_return_t
catch_mach_exception_raise_state_identity(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count);

kern_return_t
catch_mach_exception_raise_state_identity(
	__unused mach_port_t exception_port,
	__unused mach_port_t thread,
	__unused mach_port_t task,
	__unused exception_type_t type,
	__unused exception_data_t codes,
	__unused mach_msg_type_number_t code_count,
	__unused int *flavor,
	__unused thread_state_t in_state,
	__unused mach_msg_type_number_t in_state_count,
	__unused thread_state_t out_state,
	__unused mach_msg_type_number_t *out_state_count)
{
	T_FAIL("Triggered catch_mach_exception_raise_identity_protected() which shouldn't happen...");
	__builtin_unreachable();
}

/**
 * This has to be defined for linking purposes, but it's unused.
 */
kern_return_t
catch_mach_exception_raise_state(
	__unused mach_port_t exception_port,
	__unused exception_type_t type,
	__unused exception_data_t codes,
	__unused mach_msg_type_number_t code_count,
	__unused int *flavor,
	__unused thread_state_t in_state,
	__unused mach_msg_type_number_t in_state_count,
	__unused thread_state_t out_state,
	__unused mach_msg_type_number_t *out_state_count)
{
	T_FAIL("Triggered catch_mach_exception_raise_state() which shouldn't happen...");
	__builtin_unreachable();
}

kern_return_t
catch_mach_exception_raise(
	__unused mach_port_t exception_port,
	__unused mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	__unused exception_data_t codes,
	__unused mach_msg_type_number_t code_count)
{
	T_ASSERT_EQ(type, EXC_BREAKPOINT, "exc breakpoint received");

	if (cur_test == 0) {
		T_ASSERT_EQ(task, mach_task_self(), "task port should match self");
	} else {
		T_ASSERT_EQ(task, child_read, "out-of-process delivers read port");

		uint64_t type, addr;
		kern_return_t kr = mach_port_kobject(mach_task_self(), task, &type, &addr);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_kobject");

#define IKOT_TASK_READ 45 /* ipc_kobject.h */
		T_ASSERT_EQ(type, IKOT_TASK_READ, "task type must be IKOT_TASK_READ");
	}

	T_END;
}

static void *
exception_server_thread(void *arg)
{
	kern_return_t kr;
	mach_port_t exc_port = *(mach_port_t *)arg;

	/* Handle exceptions on exc_port */
	kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_msg_server_once");

	return NULL;
}

static mach_port_t
alloc_exception_port(void)
{
	kern_return_t kret;
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	kret = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kret, "mach_port_allocate exc_port");

	kret = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kret, "mach_port_insert_right exc_port");

	return exc_port;
}

T_DECL(mach_exc_port_substitute, "test read port substition back to control port"
    " for in process exception handler when dev mode is off",
    T_META_BOOTARGS_SET("amfi_dev_mode_policy=1"))     /* Turn off Developer Mode */
{
	pthread_t s_exc_thread;
	mach_port_t exc_port;
	int ret;
	kern_return_t kr;

	cur_test = 0;

	exc_port = alloc_exception_port();

	ret = pthread_create(&s_exc_thread, NULL, exception_server_thread, &exc_port);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create exception_server_thread");

	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_BREAKPOINT, exc_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "set exception ports");

	__builtin_debugtrap(); /* Generate EXC_BREAKPOINT for all platforms */

	T_FAIL("should not reach here");
	__builtin_unreachable();
}

T_DECL(mach_exc_port_substitute_oop, "test out of process exception with read port"
    " when dev mode is off",
    T_META_ENABLED(TARGET_OS_IOS),     /* Just run on iOS. Some platforms do not have dev mode */
    T_META_BOOTARGS_SET("amfi_dev_mode_policy=1"))     /* Turn off Developer Mode */
{
	pthread_t s_exc_thread;
	mach_port_t exc_port;
	int ret;
	kern_return_t kr;
	pid_t pid;
	int fds[2];

	cur_test = 1;

	exc_port = alloc_exception_port();
	ret = pthread_create(&s_exc_thread, NULL, exception_server_thread, &exc_port);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create exception_server_thread");

	ret = pipe(fds);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pipe");

	/*
	 * Set exception on self, but will be inherited by child. We can't use TFP
	 * on child when dev mode is off.
	 */
	kr = task_set_exception_ports(mach_task_self(),
	    EXC_MASK_BREAKPOINT, exc_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "set exception ports");

	pid = fork();
	T_QUIET; T_EXPECT_NE(pid, -1, "fork() should not return -1");

	if (pid) {
		close(fds[0]);
		kr = task_read_for_pid(mach_task_self(), pid, &child_read);
		T_ASSERT_EQ(kr, KERN_SUCCESS, "task_read_for_pid");

		T_LOG("Parent write to pipe");
		ret = write(fds[1], "1", 2); /* ding the child to wake up */

		waitpid(pid, NULL, 0);
		pthread_join(s_exc_thread, NULL);
	} else {
		char *buf[3];
		close(fds[1]);
		int ret = read(fds[0], buf, sizeof(buf));

		T_LOG("Child woke up from read, about to trip on bkpt");
		__builtin_debugtrap(); /* Generate EXC_BREAKPOINT for all platforms */
	}
}
