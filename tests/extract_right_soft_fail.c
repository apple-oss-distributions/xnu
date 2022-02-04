#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <signal.h>
#import <System/sys/codesign.h>

#define IKOT_TASK_CONTROL 2

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(TRUE));

static void
test_extract_immovable_task_port(pid_t pid)
{
	kern_return_t kr;
	mach_port_t tport = MACH_PORT_NULL;
	ipc_info_space_t space_info;
	ipc_info_name_array_t table;
	mach_msg_type_number_t tableCount;
	ipc_info_tree_name_array_t tree; /* unused */
	mach_msg_type_number_t treeCount; /* unused */

	mach_port_t extracted;
	mach_msg_type_name_t right;


	kr = task_for_pid(mach_task_self(), pid, &tport);
	T_EXPECT_MACH_SUCCESS(kr, "task_for_pid(), tport: 0x%x", tport);

	T_LOG("Target pid: %d", pid);

	if (pid == getpid()) {
		/* self extraction should succeed */
		kr = mach_port_extract_right(mach_task_self(), mach_task_self(), MACH_MSG_TYPE_COPY_SEND, &extracted, &right);
		T_EXPECT_MACH_SUCCESS(kr, "mach_port_extract_right() on immovable port in current space should succeed");
	} else {
		unsigned int kotype = 0, kobject = 0;
		mach_port_name_t tport_name = MACH_PORT_NULL;
		int tport_idx = 0;
		kr = mach_port_space_info(tport, &space_info, &table, &tableCount, &tree, &treeCount);
		T_EXPECT_MACH_SUCCESS(kr, "mach_port_space_info()");

		for (int i = 0; i < tableCount; i++) {
			T_LOG("Searching for task port..name: 0x%x", table[i].iin_name);
			kr = mach_port_kernel_object(tport, table[i].iin_name, &kotype, &kobject);
			if (KERN_SUCCESS == kr && kotype == IKOT_TASK_CONTROL) {
				tport_name = table[i].iin_name;
				tport_idx = i;
				break;
			} else if (kr) {
				T_LOG("mach_port_kernel_object() failed on name 0x%x, kr: 0x%x", table[i].iin_name, kr);
			}
		}

		if (!tport_name) {
			T_FAIL("Did not find task port in child's space");
		}
		T_LOG("Remote tport name: 0x%x", tport_name);
		kr = mach_port_extract_right(tport, tport_name, MACH_MSG_TYPE_COPY_SEND, &extracted, &right);
		T_EXPECT_EQ(kr, KERN_INVALID_CAPABILITY, "mach_port_extract_right() on immovable port in child's space should fail (no crash): 0x%x", kr);

		T_LOG("Still alive after extract right..");

		kr = mach_port_mod_refs(tport, tport_name, MACH_PORT_RIGHT_SEND, -table[tport_idx].iin_urefs);
		T_EXPECT_EQ(kr, KERN_INVALID_CAPABILITY, "mach_port_mod_refs() on pinned port in child's space should fail (no crash): 0x%x", kr);

		T_LOG("Still alive after deallocate..");
	}
}

T_DECL(extract_right_soft_fail, "Immovable/pinned violation on foreign task's space should not crash caller",
    T_META_CHECK_LEAKS(false))
{
	uint32_t opts = 0;
	size_t size = sizeof(&opts);
	pid_t child_pid;
	kern_return_t ret;
	int status, fd[2], fd2[2];

	T_LOG("Check if immovable control port has been enabled\n");
	ret = sysctlbyname("kern.ipc_control_port_options", &opts, &size, NULL, 0);

	if (!ret && (opts & 0x08) == 0) {
		T_SKIP("1p immovable control port hard enforcement isn't enabled");
	}

	/* extracting mach_task_self() should succeed */
	test_extract_immovable_task_port(getpid());

	ret = pipe(fd);
	T_EXPECT_NE(ret, -1, "pipe creation");

	ret = pipe(fd2);
	T_EXPECT_NE(ret, -1, "pipe creation2");

	child_pid = fork();

	if (child_pid < 0) {
		T_FAIL("fork failed()");
	}

	if (child_pid == 0) {
		char data[6];
		close(fd[0]);
		close(fd2[1]);
		write(fd[1], "wakeup", 6); /* Sync point 1 */
		close(fd[1]);

		read(fd2[0], data, 6); /* Sync point 2 */
		close(fd2[0]);
	} else {
		char data[6];
		close(fd[1]);
		close(fd2[0]);
		read(fd[0], data, 6); /* Sync point 1 */
		close(fd[0]);

		/* extracting child's immovable task port should fail without crash */
		test_extract_immovable_task_port(child_pid);

		write(fd2[1], "wakeup", 6); /* Sync point 2 */
		close(fd2[1]);

		kill(child_pid, SIGKILL);
		wait(&status);
	}
}
