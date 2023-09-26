#include <darwintest.h>
#include <darwintest_utils.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM")
	);

struct child_rc {
	int ret;
	int sig;
};

static struct child_rc
fork_child_test(void (^block)(void))
{
	struct child_rc rc = { };
	pid_t child_pid;

	child_pid = fork();

	if (child_pid == 0) {
		block();
		exit(0);
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "fork process");

	/* wait for child process to exit */
	dt_waitpid(child_pid, &rc.ret, &rc.sig, 30);
	return rc;
}

static mach_vm_address_t
get_permanent_mapping(mach_vm_size_t size)
{
	kern_return_t kr;
	mach_vm_address_t addr;

	kr = mach_vm_allocate(mach_task_self(), &addr, size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PERMANENT);

	T_ASSERT_MACH_SUCCESS(kr, "mach_vm_allocate(%lld, PERMANENT) == %p",
	    size, (void *)addr);

	*(int *)addr = 42;

	kr = mach_vm_protect(mach_task_self(), addr, size, FALSE, VM_PROT_READ);

	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_protect(PERMANENT, READ)");

	T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

	return addr;
}

T_DECL(permanent_mapping, "check permanent mappings semantics")
{
	kern_return_t kr;
	mach_vm_size_t size = 1 << 20;
	struct child_rc rc;

	T_LOG("try to bypass permanent mappings with VM_FLAGS_OVERWRITE");
	rc = fork_child_test(^{
		mach_vm_address_t addr, addr2;
		kern_return_t kr2;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		addr2 = addr;
		kr2 = mach_vm_allocate(mach_task_self(), &addr2, size,
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);

		/*
		 * because the permanent mapping wasn't removed,
		 * we should get an error.
		 */
		T_ASSERT_MACH_ERROR(kr2, KERN_NO_SPACE,
		"mach_vm_allocate(VM_FLAGS_OVERWRITE)");

		/*
		 * because the permanent mapping was neutered,
		 * accessing it should crash.
		 */
		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});
	T_EXPECT_EQ(rc.sig, SIGBUS, "accessing the mapping caused a SIGBUS");

	T_LOG("try to bypass permanent mappings with a VM_PROT_COPY mprotect");
	rc = fork_child_test(^{
		kern_return_t kr2;
		mach_vm_address_t addr;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		kr2 = mach_vm_protect(mach_task_self(), addr, size, TRUE,
		VM_PROT_COPY | VM_PROT_DEFAULT);

		/*
		 * because the permanent mapping wasn't removed,
		 * we should get an error.
		 */
		T_ASSERT_MACH_ERROR(kr2, KERN_NO_SPACE,
		"mach_vm_protect(VM_PROT_COPY)");

		/*
		 * because the permanent mapping was neutered,
		 * accessing it should crash.
		 */
		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});
	T_EXPECT_EQ(rc.sig, SIGBUS, "accessing the mapping caused a SIGBUS");

	T_LOG("try to bypass permanent mappings with a vm_remap");
	rc = fork_child_test(^{
		kern_return_t kr2;
		mach_vm_address_t addr, remap_addr, addr2;
		vm_prot_t cur_prot, max_prot;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		addr2 = 0;
		kr2 = mach_vm_allocate(mach_task_self(), &addr2, size,
		VM_FLAGS_ANYWHERE);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr2, "vm_allocate()");

		remap_addr = addr;
		kr2 = mach_vm_remap(mach_task_self(), &remap_addr, size, 0,
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
		mach_task_self(), addr2, TRUE,
		&cur_prot, &max_prot, VM_INHERIT_DEFAULT);

		/*
		 * because the permanent mapping wasn't removed,
		 * we should get an error.
		 */
		T_ASSERT_MACH_ERROR(kr2, KERN_NO_SPACE,
		"mach_vm_remap()");

		/*
		 * because the permanent mapping was neutered,
		 * accessing it should crash.
		 */
		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});
	T_EXPECT_EQ(rc.sig, SIGBUS, "accessing the mapping caused a SIGBUS");

	T_LOG("try to bypass permanent mappings with a vm_deallocate");
	rc = fork_child_test(^{
		kern_return_t kr2;
		mach_vm_address_t addr;

		addr = get_permanent_mapping(size);

		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");

		kr2 = mach_vm_deallocate(mach_task_self(), addr, size);

		/*
		 * the permanent mapping wasn't removed but was made
		 * inaccessible; we should not get an error.
		 */
		T_ASSERT_MACH_SUCCESS(kr2, "mach_vm_deallocate()");

		/*
		 * because the permanent mapping was neutered,
		 * accessing it should crash.
		 */
		T_QUIET; T_EXPECT_EQ(*(int *)addr, 42, "we can still read what we wrote");
	});
	T_EXPECT_EQ(rc.sig, SIGBUS, "accessing the mapping caused a SIGBUS");
}
