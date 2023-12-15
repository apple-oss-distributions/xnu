#include <errno.h>
#include <fcntl.h>
#include <kern/kcdata.h>
#include <mach/kern_return.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/fsctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include <mach/mach.h>
#include <excserver.h>
#include <dispatch/dispatch.h>
#import <Foundation/Foundation.h>
#import <System/corpses/task_corpse.h>
#include <kdd.h>
#include <kern/kern_cdata.h>
#include <sys/reason.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_OWNER("y_feigelson"),
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

static int verbose = 0;

// KDBG_TRIAGE_VM_OBJECT_NO_PAGER_FORCED_UNMOUNT
#define FORCED_UNMOUNT_ERROR "Object has no pager because the backing vnode was force unmounted"
// KDBG_TRIAGE_VM_OBJECT_NO_PAGER_UNGRAFT
#define UNGRAFTED_ERROR "Object has no pager because the backing vnode was ungrafted"

static dispatch_semaphore_t sync_sema;
static char* current_expected_triage_string;

/* Use darwintests' launch and waitpid */
static int
my_system(const char *command, const char *arg)
{
	pid_t pid;
	int ret;
	const char *argv[] = {
		command,
		arg,
		verbose ? "-v" : "",
		NULL
	};

	dt_launch_tool(&pid, (char **)(void *)argv, FALSE, NULL, NULL);
	// Status and signal will be empty since we took over exception handling
	dt_waitpid(pid, NULL, NULL, 100);
	
	return 0;
}

static int
system_corpse_limit_reached(void)
{
	size_t output_size;
	int total_corpse_count;
	int ret;

	output_size = sizeof(total_corpse_count);

	ret = sysctlbyname("kern.total_corpses_count", &total_corpse_count, &output_size, NULL, 0);
	if (ret != 0) {
		T_LOG("sysctlbyname kern.total_corpses_count returned error: %d", ret);
		return TRUE;
	}

	T_LOG("System corpse count is %d", total_corpse_count);

	/* Abort the test if total_corpse_count is greater than equal to 4 */
	// TODOyfeig check this out
	if (total_corpse_count >= 4) {
		return TRUE;
	}

	return FALSE;
}

/* Iterate corpse kcdata and verify `current_expected_triage_string` is found */
void
verify_corpse_data(mach_port_t task, mach_vm_address_t corpse_addr, size_t corpse_size)
{
	void * result                   = NULL;
	mach_vm_address_t start_address;
	mach_vm_address_t end_address;;
	uint8_t * local_start;
	uint64_t local_len;
	kern_return_t r;

	uint32_t t                          = 0;
	uint32_t s                          = 0;
	uint64_t f                          = 0;
	uint64_t crashed_thread_id_reported = 0;
	void * d                            = NULL;
	int i                               = 0;
	kern_return_t kret                  = KERN_SUCCESS;
	task_crashinfo_item_t corpse_data   = NULL;

	T_LOG("Verifiyng corpse data");
	start_address = trunc_page((size_t)corpse_addr);
	end_address  = round_page(corpse_addr + corpse_size);
	r = task_map_corpse_info_64(mach_task_self(), task, (mach_vm_address_t *)&local_start, &local_len);
	corpse_addr = (mach_vm_address_t)local_start;
	start_address = (mach_vm_address_t)local_start;
	corpse_size = local_len;
	if (r == KERN_SUCCESS) {
		corpse_data = malloc(corpse_size);
		if (corpse_data) {
			void * src = &local_start[(mach_vm_address_t)corpse_addr - start_address];
			memcpy(corpse_data, src, corpse_size);
		} else {
			T_FAIL("Failed to malloc for corpse data");
			return;
		}
		vm_deallocate(mach_task_self(), (uintptr_t)local_start, local_len);
	}

	kcdata_iter_t iter = kcdata_iter(corpse_data, corpse_size);
	KCDataType * kcd_type = NULL;

	KCDATA_ITER_FOREACH(iter)
	{
		i++;
		t        = kcdata_iter_type(iter);
		s        = kcdata_iter_size(iter);
		f        = kcdata_iter_flags(iter);
		d        = kcdata_iter_payload(iter);
		kcd_type = getKCDataTypeForID(t);

		if (t == TASK_CRASHINFO_KERNEL_TRIAGE_INFO_V1) {
			struct kernel_triage_info_v1 kt = *(struct kernel_triage_info_v1 *) d;

			for (char* str_iter = &kt; str_iter < (char*)&kt + sizeof(struct kernel_triage_info_v1); str_iter += MAX_TRIAGE_STRING_LEN) {
				if (strlen(str_iter) && strstr(str_iter, current_expected_triage_string)) {
					free(corpse_data);
					T_PASS("Found expected crash triage string in corpse kcdata:\n`%s`", kt.triage_string1);
					return;
				}
			}
		}
	}
	
	free(corpse_data);
	if (KCDATA_ITER_FOREACH_FAILED(iter)) {
		T_FAIL("kcdata iteration failed");
	}

	T_FAIL("Didn't find expected crash string.\nExpected: `%s`", current_expected_triage_string);
}

/* Mach exception handler routines */
kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
                           mach_port_t thread,
                           mach_port_t task,
                           exception_type_t exception,
                           mach_exception_data_t code,
                           mach_msg_type_number_t codeCnt)
{
	if (exception == EXC_CORPSE_NOTIFY) {
		T_LOG("successfully caught EXC_CORPSE_NOTIFY %d code[0] = 0x%016llx at 0x%016llx", exception, code[0], code[1]);
		verify_corpse_data(task, (mach_vm_address_t)code[0], (size_t)code[1]);
		dispatch_semaphore_signal(sync_sema);
		return KERN_SUCCESS;
	}

	T_LOG("caught %d %s(%d) at 0x%016llx returning KERN_FAILURE", exception, mach_error_string((int)code[0]), (int)code[0],
	       code[1]);
	return KERN_FAILURE;
}

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
                                 exception_type_t exception,
                                 const mach_exception_data_t code,
                                 mach_msg_type_number_t codeCnt,
                                 int * flavor,
                                 const thread_state_t old_state,
                                 mach_msg_type_number_t old_stateCnt,
                                 thread_state_t new_state,
                                 mach_msg_type_number_t * new_stateCnt)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
                                          mach_port_t thread,
                                          mach_port_t task,
                                          exception_type_t exception,
                                          mach_exception_data_t code,
                                          mach_msg_type_number_t codeCnt,
                                          int * flavor,
                                          thread_state_t old_state,
                                          mach_msg_type_number_t old_stateCnt,
                                          thread_state_t new_state,
                                          mach_msg_type_number_t * new_stateCnt)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_identity_protected(
	__unused mach_port_t      exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     code,
	mach_msg_type_number_t    codeCnt)
{
	return KERN_NOT_SUPPORTED;
}


/*
 * Setup exception handling port for EXC_CORPSE_NOTIFY.
 * Runs mach_msg_server once for receiving exception messages from kernel
 */
static void *
setup_mach_server(void * arg __unused)
{
	kern_return_t kret;
	mach_port_t exception_port;

	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
	T_EXPECT_MACH_SUCCESS(kret, "mach_port_allocate: %s (%d)", mach_error_string(kret), kret);
	
	kret = mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	T_EXPECT_MACH_SUCCESS(kret, "mach_port_insert_right: %s (%d)", mach_error_string(kret), kret);
	
	kret = task_set_exception_ports(mach_task_self(), EXC_MASK_CORPSE_NOTIFY, exception_port,
	                                EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, 0);
	T_EXPECT_MACH_SUCCESS(kret, "task_set_exception_ports: %s (%d)", mach_error_string(kret), kret);

	dispatch_semaphore_signal(sync_sema);

	kret = mach_msg_server(mach_exc_server, MACH_MSG_SIZE_RELIABLE, exception_port, 0);
	T_EXPECT_MACH_SUCCESS(kret, "mach_msg_server: %s (%d)", mach_error_string(kret), kret);
	
	return NULL;
}

static void
parse_args(int argc, char** argv)
{
	char c;
	opterr = 0;
    optind = 0;
 
    while ((c = getopt(argc, argv, "v")) != -1) {
        switch (c) {
        case 'v':
            verbose = 1;
            break;
        }
    }
}

/* Perform necessary setup prior to running crash program */
static void
setup_for_crash()
{
	T_SETUPBEGIN;

	int ret;
	pthread_t handle_thread;

	ret = system_corpse_limit_reached();
	if (ret) {
		T_SKIP("Too many processes already crashing, can't test corpses. Aborting test.");
		return;
	}

	sync_sema = dispatch_semaphore_create(0);

	ret = pthread_create(&handle_thread, NULL, setup_mach_server, NULL);
	T_QUIET; T_EXPECT_EQ(ret, 0, "pthread_create failed");

	T_SETUPEND;
}

/* Run the helper with the chosen test number */ 
static void
run_test(const char* test_num, int argc, char** argv)
{
	parse_args(argc, argv); // TODOyfeig is there really no global setup in darwintests?
	setup_for_crash();

	dispatch_semaphore_wait(sync_sema, DISPATCH_TIME_FOREVER); // Wait for exception handler setup
	my_system("./test_vm_no_pager_helper", test_num);
	dispatch_semaphore_wait(sync_sema, DISPATCH_TIME_FOREVER); // Wait for corpse kcdata processing
}


/* Test Declarations  */
T_DECL(vm_no_pager_force_unmount, "test correct detection and propagation of reason for not having a pager (forced unmount)",
	T_META_IGNORECRASHES(".*test_vm_no_pager.*"),
	T_META_ASROOT(true))
{
	current_expected_triage_string = FORCED_UNMOUNT_ERROR;
	run_test("1", argc, argv);
}

T_DECL(vm_no_pager_ungraft, "test correct detection and propagation of reason for not having a pager (ungraft)",
    T_META_IGNORECRASHES(".*test_vm_no_pager.*"),
    T_META_ASROOT(true))
{
	current_expected_triage_string = UNGRAFTED_ERROR;
	run_test("2", argc, argv);
}
