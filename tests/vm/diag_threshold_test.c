/*
 *
 *  DiagThresholdTest.c
 *  DiagThresholdTest
 *  Test suite for the memory diagnostics thresholds kernel.
 *  Copyright (c) 2022 Apple Inc. All rights reserved.
 *
 */


#include "vm/diag_threshold_test.h"
#include <sys/kern_memorystatus.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#define TIMEOUT_MAX_SECONDS 10
/**
 * Preprocessor declarations
 */
/**
 * Global variables
 */
static mach_port_t         exception_port;                                            /**   Port used to receive exception information*/
static semaphore_t         exception_semaphore;                                       /**   Termination semaphore when the exception is caught */
static exception_mask_t    mask                        =  EXC_MASK_CORPSE_NOTIFY;     /**   Kind of exception we are interested in*/
static char                main_thread_name[COMMAND_LINE_MAX];                        /**   Name of the main thread, for restauration */
static struct sigaction    original_action;                                           /**   Original signal handler for the process */

/**
 * Data types private
 */

static test_context_t *current_test_info;                                              /**   Data type used to handle working information on the current test*/
/**
 * Function prototypes (private)
 */
static void prepare_harness(void);                                                     /**   Preparation of the exception port and other miscs */
static void init_mach_exceptions_port(void);                                           /**   Creation of the exception port */
static void wait_for_exceptions_thread(test_context_t *tests_info);                    /**   Wait for for the startup of the exception handler thread */
static void *test_executor_thread(void *);                                             /**   Code of the exception handler thread */
static void wait_for_executor_thread(test_context_t *info);                            /**   Wait for the initialization of the worker thread */
static void create_exception_handler_thread(test_context_t *);                         /**   Creator of the exception handler thread */
static void create_executor_handler_thread(test_context_t *param);                     /**   Creation of the worker thread, the one that performs really the test code */
static void terminate_exception_handler_thread(test_context_t *);                      /**   Order to terminate the current exception handler thread (by sending a user posix signal)*/
static void terminate_executor_handler_thread(test_context_t *param);                  /**   Order to terminate the current worker thread (by sending a user posix signal)*/
static void set_exception_ports(test_context_t *param);                                /**   Function that sets the exception port for the current test */
static void save_exception_ports(test_context_t *param);                               /**   Save the current exception mach configuration to restore after the test */
static void restore_exception_ports(test_context_t *param);                            /**   Restauration of the exception mach configuration after each test */
static void wait_for_exceptions_ready(test_context_t *info);                           /**   Synch point between the worker and the test harness, to allow workers to capture exceptions */
static void set_sig_handler(void);                                                     /**   Initialization of the SIGUSR1 posix signal handler, used to terminate threads */
static void reset_sig_handler(void);                                                   /**   Reset the signal handler */
static void enable_coredumps(void);                                                    /**   Since debug of this app is not possible with lldb, that allows to create core files for debugging */
static void deinit_mach_exceptions_port(void);                                         /**   Destroys the mach port used to exceptions*/
static void execute_one_test(test_case_t *test);                                       /**   Perform the exeuction of a single test */
static void remove_harness(void);                                                      /**   Remove the test harness for this process*/
static uint64_t get_hw_memory_size(void);                                              /**   Get the ammount of RAM available on this device */
static const char *g_sysctl_memsize_name = "hw.memsize";

void
diag_mem_threshold_set_setup(__unused test_case_t *test)
{
	T_QUIET; T_ASSERT_POSIX_ZERO( pthread_setname_np("Test controller"), "Verification thread set name");
	enable_coredumps();

	set_sig_handler();
	prepare_harness();
	execute_one_test(test);
}
/**
 * Shutdown the test environment
 */
void
diag_mem_threshold_set_shutdown(void)
{
	T_QUIET; T_ASSERT_POSIX_ZERO( pthread_getname_np(pthread_self(), main_thread_name, sizeof(main_thread_name)), "Verification thread get name");
	remove_harness();
	reset_sig_handler();
	deinit_mach_exceptions_port();
}

/**
 * Once the test worker is created, this function waits for a period of time (TIMEOUT_MAX_SECONDS) for an exception
 * and returns TRUE if the exception is seen, or FALSE if not.
 * - Parameter param: test execution information, used to mark in the test if the exception is seen.
 * */
bool
diag_mem_threshold_wait_for_exception(test_context_t *param)
{
	int seconds_execution = 0;
	param->exception_seen = FALSE;
	mach_timespec_t wait_time = {.tv_sec = 1, .tv_nsec = 0};
	while (seconds_execution++ < TIMEOUT_MAX_SECONDS) {
		if (!semaphore_timedwait(exception_semaphore, wait_time)) {
			param->exception_seen = TRUE;
			diag_mem_threshold_log_test("Semaphore done, exiting\n");
			/* Cleanup any residual values in the semahore */
			wait_time.tv_sec = 0;
			while (!semaphore_timedwait(exception_semaphore, wait_time)) {
				NULL;
			}
			return TRUE;
		}

		diag_mem_threshold_log_test("Waiting\n");
	}

	return FALSE;
}

/**
 * Execute only one test
 */
void
execute_one_test(test_case_t *test)
{
	test_context_t info = {
		.test = test,
		.exception_semaphore = exception_semaphore,
		.exception_thread_start_sema = dispatch_semaphore_create(0),
		.executor_thread_start_sema = dispatch_semaphore_create(0),
		.executor_thread_end_sema = dispatch_semaphore_create(0),
		.executor_ready_for_exceptions = dispatch_semaphore_create(0),
	};
	uint64_t this_system_ram_size = get_hw_memory_size();
	current_test_info = &info;
	/** If this test required a certain ammount of memory in the device, and is
	 * not present, just pass the test.
	 */
	if (test->required_minimum_hw_ram_size != 0) {
		if (this_system_ram_size < test->required_minimum_hw_ram_size) {
			T_SKIP("This system have less memory as required to run this test (Required %llu MB found %llu MB). Skipping", test->required_minimum_hw_ram_size >> 20ULL, this_system_ram_size >> 20ULL);
			test->did_pass = TRUE;
			return;
		}
	}
	diag_mem_threshold_log_test("This system have %llu MB RAM\n", (this_system_ram_size >> 20ULL));

	save_exception_ports(&info);
	create_exception_handler_thread(&info);
	create_executor_handler_thread(&info);
	set_exception_ports(&info);

	wait_for_exceptions_thread(&info);
	wait_for_executor_thread(&info);
	wait_for_exceptions_ready(&info);
	if (test->exceptions_handled_in_test == false) {
		bool wait_result = diag_mem_threshold_wait_for_exception(&info);

		/**   If the test expects to have an exception at end, and is seen.. */
		if ((test->result_already_present == FALSE) && (wait_result == TRUE)) {
			test->did_pass = TRUE;
		} else if (test->exception_not_expected == TRUE && wait_result == FALSE) {
			/**   If the test expects to NOT have an exception at end, and NOT seen.. */
			test->did_pass = TRUE;
		} else {
			test->did_pass = FALSE;
		}
	} else {
		pthread_join(info.executor_handler_thread_id, NULL);
	}
	T_EXPECT_TRUE(test->did_pass, "Test result");
	restore_exception_ports(&info);

	if (test->exceptions_handled_in_test == false) {
		terminate_executor_handler_thread(&info);
	}
	terminate_exception_handler_thread(&info);
	if (info.test->did_pass) {
		diag_mem_threshold_log_test("Test success\n");
	} else {
		diag_mem_threshold_log_test("Test failed\n");
	}
}
/**
 * Thread that really performs the test execution, sets its thread name,  signals
 * the semaphore of executor ready and calls to the test code. Finally
 * it marks another semaphore to signal that the test code is complete.
 * - Parameter params: parameters of the test execution
 */
static void *
test_executor_thread(void *params)
{
	char thread_name[MAX_MESSAGE];
	test_context_t info = *(test_context_t *)params;
	snprintf(thread_name, sizeof(thread_name), "Exec: %s", info.test->short_name);
	pthread_setname_np(thread_name);
	diag_mem_threshold_log_test("Startup of executor for test %s\n", info.test->short_name);
	dispatch_semaphore_signal(info.executor_thread_start_sema);
	info.test->test_code(info.test, &info);
	dispatch_semaphore_signal(info.executor_thread_end_sema);
	return NULL;
}

/**
 * Set the exception port for the current task, did not manage to make it work with execution thread..
 * - Parameter param: paramers of the exeuction, not used at the moment
 */
static void
set_exception_ports(__unused test_context_t *param)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, task_set_exception_ports(mach_task_self(), mask, exception_port, (exception_behavior_t) (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES | EXCEPTION_STATE_IDENTITY), MACHINE_THREAD_STATE), "Cannot set exception port");
}
/**
 * Allocates and sets rights for the exceptions port
 */
static void
init_mach_exceptions_port(void)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port), "Verification allocation port for exceptions");
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND), "Verification set port rights");
}
/**
 * Destroys the used mach port for exceptions.
 */
static void
deinit_mach_exceptions_port(void)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, mach_port_deallocate(mach_task_self(), exception_port), "Verification exceptions port deallocation");
}
/**
 * Saves the current task exception port on the current test context.
 * - Parameter info: test context.
 */
static void
save_exception_ports(test_context_t *info)
{
	info->size_mask = NUM_MASKS;
	kern_return_t ret;
	ret  = task_get_exception_ports(
		mach_task_self(),
		mask,
		info->old_mask,
		&info->size_mask,
		info->old_handlers,
		info->old_behaviors,
		info->old_flavors);
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, ret, "Verification get old exception ports");
}
/**
 * Once the test is completed, this function restores all the mach task exception configuration to its original state
 * - Parameter info: test context.
 */
static void
restore_exception_ports(test_context_t *info)
{
	kern_return_t ret;
	ret  = task_swap_exception_ports(
		mach_task_self(),
		mask,
		MACH_PORT_NULL,
		EXCEPTION_DEFAULT,
		THREAD_STATE_NONE,
		(exception_mask_array_t) &info->old_mask,
		&info->size_mask,
		info->old_handlers,
		info->old_behaviors,
		info->old_flavors);
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, ret, "Verification restore exception ports");
}
/**
 * Create the pthread used to handle exceptions from this test.
 * - Parameter param: Test context.
 */
static void
create_exception_handler_thread(test_context_t *param)
{
	T_QUIET; T_ASSERT_POSIX_ZERO( pthread_create(&param->exception_handler_thread_id, NULL, exception_thread, (void *)param), "Creation of exception handler thread");
}
/**
 * Create the pthread used to really run the test code
 * - Parameter param: Test context.
 */
static void
create_executor_handler_thread(test_context_t *param)
{
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&param->executor_handler_thread_id, NULL, test_executor_thread, (void *)param), "Creation test worker thread");
}
/**
 * Terminates the exception handler by sending a SIGUSR1 posix signal to the thread. On arrival it will terminate
 * - Parameter param: Test context.
 */
static void
terminate_exception_handler_thread(test_context_t *param)
{
	void *ret_value;
	T_QUIET; T_ASSERT_POSIX_ZERO( pthread_kill(param->exception_handler_thread_id, SIGUSR1), "Verification send terminate signal to the exception handler thread");
	T_QUIET; T_ASSERT_POSIX_ZERO( pthread_join(param->exception_handler_thread_id, &ret_value), "Verification join to exception handler thread");
}
/**
 * Terminates the test code executior  by sending a SIGUSR1 posix signal to the thread. On arrival it will terminate
 * - Parameter param: Test context.
 */
static void
terminate_executor_handler_thread(test_context_t *param)
{
	void *ret_value;
	int pthread_kill_val =  pthread_kill(param->executor_handler_thread_id, SIGUSR1);
	T_QUIET; T_ASSERT_TRUE((pthread_kill_val == 0 || pthread_kill_val == ESRCH) ? TRUE : FALSE, "Verification send terminate to worker thread");
	T_QUIET; T_ASSERT_POSIX_ZERO( pthread_join(param->executor_handler_thread_id, &ret_value), "Verification join to the test worker thread");
}

/**
 * Exception handler thread. Receives the mach exception port messages, and dispatch them by using
 * a standard mach_exc_server. It reads the messages one by one to allow some logging.
 * Also sets its thread name to the EH test_name (EH from exception handler).
 * Signals to the main thread that is ready to run the test by using the semaphore exception_thread_start_sema
 *
 * Please note that, in order to avoid problems it creates a working copy of the thread context, so, if the main loop
 * discards the current test context, it can work with a copy.
 * - Parameter param: Test context.
 */
void *
exception_thread(void *params)
{
	char thread_name[MAX_MESSAGE];
	test_context_t info = *(test_context_t *)params;
	snprintf(thread_name, sizeof(thread_name), "EH %s", info.test->short_name);
	pthread_setname_np(thread_name);
	diag_mem_threshold_log_test("Startup of exception handler for test %s\n", info.test->short_name);
	dispatch_semaphore_signal(info.exception_thread_start_sema);

	while (1) {
		/* Handle exceptions on exc_port */
		T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, mach_msg_server_once(mach_exc_server, 4096, exception_port, 0), "Verification of obtain a exception message");
		diag_mem_threshold_log_test("Exception arrived\n");
	}
	return NULL;
}

/**
 * Helper to test the diagnostics threshold limits for the tests. In order to ensure that everything works
 * as expected, it also verifies the limit agains the ledger.
 * - Parameter limit_param: new limit in bytes, -1 means "disable the threshold limit"
 *
 */
bool
set_memory_diagnostics_threshold_limits(uint64_t limit_param, bool assert_on_error)
{
	memorystatus_diag_memlimit_properties_t limit;
	memorystatus_diag_memlimit_properties_t limit_verify;
	diag_mem_threshold_log_test("Set threshold limit to %d MB\n", limit_param >> 20);
	int pid = getpid();
	limit.memlimit = limit_param;
	int retValue = memorystatus_control(
		MEMORYSTATUS_CMD_SET_DIAG_LIMIT,
		pid,
		0,
		&limit, sizeof(limit)
		);
	T_ASSERT_MACH_SUCCESS( retValue, "Verification diagnostics threshold limit adjustment");
	if (assert_on_error) {
		retValue = memorystatus_control(
			MEMORYSTATUS_CMD_GET_DIAG_LIMIT,
			pid,
			0,
			&limit_verify, sizeof(limit_verify)
			);
		T_ASSERT_MACH_SUCCESS(retValue, "Verification memory diagnostics limit");

		T_ASSERT_EQ(limit.memlimit, limit_verify.memlimit, "Verification of diag threshold mem limit");
	}
	return (retValue == KERN_SUCCESS) ? true : false;
}

/**
 * Helper that allows to waste memory and afterwards free it. It uses kernel memory to ensure is allocated really.
 * - Parameter ammount: ammount of memory to waste in bytes.
 */
void
diag_mem_threshold_waste_memory(uint64_t ammount)
{
	mach_vm_address_t global_addr = 0;
	vm_size_t global_size = ammount;
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, mach_vm_allocate(mach_task_self(), &global_addr, global_size, VM_FLAGS_ANYWHERE ), "Allocate memory for test threshold");

	diag_mem_threshold_log_test("Going to waste memory (%d MB)\n", ammount >> 20);
	memset((void *)global_addr, 0xaa, ammount);
	diag_mem_threshold_log_test("Memory wasted\n");

	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, mach_vm_deallocate(mach_task_self(), global_addr, global_size), "Deallocation of memory from test threshold");
}
/**
 * Helper that allows to set a jetsam watermark
 * - Parameter ammount: ammount of memory to waste in bytes.
 */
void
diag_mem_set_jetsam_watermark(uint ammount)
{
	diag_mem_threshold_log_test("Set jetsam watermark to %d MB\n", ammount >> 20);
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid(), ammount >> 20, NULL, 0), "Set jetsam watermark");
}
/**
 * Helper that allows to set a jetsam watermark
 * - Parameter ammount: ammount of memory to waste in bytes.
 */
void
diag_mem_set_jetsam_limit(uint ammount)
{
	diag_mem_threshold_log_test("Set jetsam limit to %d MB\n", ammount >> 20);
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), ammount >> 20, NULL, 0), "Set jetsam watermark");
}

/**
 * Standard mach exception handler invoked by mach_server
 * - Parameters:
 *   - exception_port: see mach documentation
 *   - thread: see mach documentation
 *   - task: see mach documentation
 *   - exception: see mach documentation
 *   - code: see mach documentation
 *   - code_count: see mach documentation
 */
kern_return_t
catch_mach_exception_raise( __unused mach_port_t  port, __unused  mach_port_t  thread, __unused  mach_port_t  task, __unused exception_type_t  exception, __unused exception_data_t  code, __unused  mach_msg_type_number_t  code_count)
{
	#ifdef VERBOSE
	diag_mem_threshold_log_test("catch_mach_exception_raise:Have exception (expected) type 0x%x code len %d\n", exception, code_count);
	unsigned int j;
	for (j = 0; j < code_count << 1; j++) {
		diag_mem_threshold_log_test("catch_mach_exception_raise:Code[%d]=0x%x\n", j, code[j]);
	}
	#endif
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, semaphore_signal(exception_semaphore), "Verification of signal of exception semaphore");
	return KERN_SUCCESS;
}
/**
 * Standard mach exception handler invoked by mach_server, not used in this application
 * - Parameters:
 *   - exception_port: see mach documentation
 *   - exception: see mach documentation
 *   - code: see mach documentation
 *   - codeCnt: see mach documentation
 *   - flavor: see mach documentation
 *   - old_state: see mach documentation
 *   - old_stateCnt: see mach documentation
 *   - new_state: see mach documentation
 *   - new_stateCnt: see mach documentation
 */
kern_return_t
catch_mach_exception_raise_state(__unused mach_port_t port, __unused exception_type_t exception, __unused const exception_data_t code, __unused mach_msg_type_number_t codeCnt, __unused int *flavor, __unused const thread_state_t old_state, __unused mach_msg_type_number_t old_stateCnt, __unused thread_state_t new_state, __unused mach_msg_type_number_t *new_stateCnt)
{
	diag_mem_threshold_log_test("catch_mach_exception_raise_state:Have exception (expected) type 0x%x code len %d\n", exception, codeCnt);
	T_QUIET; T_ASSERT_TRUE(FALSE, "Unexpected exception handler called");
	return KERN_FAILURE;
}

/**
 * Standard mach exception handler invoked by mach_server, not used in this application
 * - Parameters:
 *   - exception_port: see mach documentation
 *   - exception: see mach documentation
 *   - code: see mach documentation
 *   - codeCnt: see mach documentation
 *   - flavor: see mach documentation
 *   - old_state: see mach documentation
 *   - old_stateCnt: see mach documentation
 *   - new_state: see mach documentation
 *   - new_stateCnt: see mach documentation
 */
kern_return_t
catch_mach_exception_raise_state_identity(__unused mach_port_t port, __unused mach_port_t thread, __unused mach_port_t task, __unused exception_type_t exception, __unused mach_exception_data_t code, __unused mach_msg_type_number_t codeCnt, __unused int *flavor, __unused thread_state_t old_state, __unused mach_msg_type_number_t old_stateCnt, __unused thread_state_t new_state, __unused mach_msg_type_number_t *new_stateCnt)
{
	#ifdef VERBOSE
	diag_mem_threshold_log_test("catch_mach_exception_raise_state_identity:Have exception (expected)  exception_port %x  thread %x task %x exception %x code %x codeCnt %x flavor %x old_statd %x old_stateCnt %x new_state %x new_stateCnt %x",
	    port,
	    thread,
	    task,
	    exception,
	    *code,
	    codeCnt,
	    *flavor,
	    old_state,
	    old_stateCnt,
	    new_state,
	    new_stateCnt);

	for (unsigned int j = 0; j < codeCnt; j++) {
		diag_mem_threshold_log_test("catch_mach_exception_raise_state_identity:Code[%d]=0x%llx\n", j, code[j]);
	}
	#endif
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, semaphore_signal(exception_semaphore), "Verification of signal of exception semaphore");
	diag_mem_threshold_log_test("catch_mach_exception_raise_state_identity:Semaphore signalled");
	return KERN_SUCCESS;
}
/**
 * getter of the current exception port as a helper.
 */
mach_port_t
diag_mem_threshold_get_exception_port(void)
{
	return exception_port;
}
/**
 * Getter of the configured exceptions masks for this execution
 */
exception_mask_t
diag_mem_threshold_get_exceptions_mask(void)
{
	return mask;
}
/**
 *  Wait until the exceptions thread is ready.
 * - Parameter info: test context.
 */
static void
wait_for_exceptions_thread(test_context_t *info)
{
	dispatch_semaphore_wait(info->exception_thread_start_sema, DISPATCH_TIME_FOREVER);
}
/**
 *  Wait until the executoir thread is ready.
 * - Parameter info: test context.
 */
static void
wait_for_executor_thread(test_context_t *info)
{
	dispatch_semaphore_wait(info->executor_thread_start_sema, DISPATCH_TIME_FOREVER);
}
/**
 *  Wait until the executor thread is ready to accept exceptions from the test launcher. It is used to handle also internally
 *  exceptions by the test worker thread. An example of that is the double limit test, where an app sets a limit, it passes it, and
 *  wants to re-enable the threshold limt. In this case part of the exception verification is done inside the test, and the rest (second exception)
 *  is delegated to the test launcher. Test launcher will not consider exceptions before this semaphore is signalled.
 * - Parameter info: test context.
 */
static void
wait_for_exceptions_ready(test_context_t *info)
{
	dispatch_semaphore_wait(info->executor_ready_for_exceptions, DISPATCH_TIME_FOREVER);
}
/* Temporally block signals while logging */
static sigset_t
thread_block_signal(int blocking_signal_mask)
{
	sigset_t   signal_mask;
	sigset_t   signal_mask_return;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, blocking_signal_mask);
	int mask_set_ret_value = pthread_sigmask(SIG_BLOCK, &signal_mask, &signal_mask_return);
	assert( mask_set_ret_value == 0);
	return signal_mask_return;
}
/* Restore the signals configuration */
static void
thread_unblock_signal(sigset_t unblocking_signal_mask)
{
	assert(pthread_sigmask(SIG_SETMASK, &unblocking_signal_mask, NULL) == 0);
}
/**
 *
 * Simple log routine that adds information about the thread that is logging
 */
void
diag_mem_threshold_log_test(const char *fmt, ...)
{
	char log_string[MAX_MESSAGE];
	char thread_name[MAX_MESSAGE];
	va_list valist;
	/**
	 * To avoid problems with the xnu testing library log support, lets avoid signals while
	 * logging
	 */
	sigset_t sig_mask = thread_block_signal(SIGUSR1);

	va_start(valist, fmt);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	vsnprintf(log_string, sizeof(log_string), (const char *)fmt, valist);
#pragma clang diagnostic pop

	assert(pthread_getname_np(pthread_self(), thread_name, sizeof(thread_name)) == 0);
	T_LOG("[%-32.32s] %s", thread_name, log_string);
	/* And restore the signals */
	thread_unblock_signal(sig_mask);
}

/**
 * Prepare all the semaphores and other stuff required for all the tests
 */
static void
prepare_harness(void)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, semaphore_create(mach_task_self(), &exception_semaphore, SYNC_POLICY_FIFO, 0), "Creation of semaphore for exceptions");
	init_mach_exceptions_port();
}

/**
 * Prepare all the semaphores and other stuff required for all the tests
 */
static void
remove_harness(void)
{
	T_QUIET; T_ASSERT_EQ(KERN_SUCCESS, semaphore_destroy(mach_task_self(), exception_semaphore), "Destruction of exceptions semaphore");
	deinit_mach_exceptions_port();
}

/**
 * Handler of the SIGUSR1 signal, just terminates the current thread.
 */
static void
termination_handler(__unused int signo, __unused  siginfo_t *info, __unused void *extra)
{
	diag_mem_threshold_log_test("End of thread\n");
	pthread_exit(NULL);
	// We should never reach that point..
	T_QUIET; T_ASSERT_MACH_SUCCESS(0, "Cannot kill this thread");
}
/**
 * Standard function to set a singal handler routine. Sets the handler for SIGUSR1 to the
 * termination_handler routine, and indeed terminates current thread.
 */
static void
set_sig_handler(void)
{
	struct sigaction action;

	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = termination_handler;

	T_QUIET; T_ASSERT_MACH_SUCCESS(sigaction(SIGUSR1, &action, &original_action), "Verification of adjustment of signal handler");
}
/**
 * Standard function to set a singal handler routine. Sets the handler for SIGUSR1 to the
 * termination_handler routine, and indeed terminates current thread.
 */
static void
reset_sig_handler(void)
{
	T_QUIET; T_ASSERT_MACH_SUCCESS(sigaction(SIGUSR1, &original_action, NULL), "Verification of reset signal handler");
}
/**
 * Since lldb do not work with CORPSE exceptions, that allows to
 * store a task coredump for further analysis.
 */
static void
enable_coredumps(void)
{
	struct rlimit limits = {
		.rlim_cur = UINT64_MAX,
		.rlim_max = UINT64_MAX
	};
	T_QUIET; T_ASSERT_MACH_SUCCESS( getrlimit(RLIMIT_CORE, &limits), "obtain coredump limits");
	limits.rlim_cur = 0x7fffffffffffffff;
	T_QUIET; T_ASSERT_MACH_SUCCESS( setrlimit(RLIMIT_CORE, &limits), "set coredump limits");
}

/**
 * Return the ammount of memory available on this device
 */
static uint64_t
get_hw_memory_size(void)
{
	int ret;
	uint64_t max_mem;
	size_t max_mem_size = sizeof(max_mem);
	ret = sysctlbyname(g_sysctl_memsize_name, &max_mem, &max_mem_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memsize sysctl failed");
	return max_mem;
}
