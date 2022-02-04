#include <mach/port.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <sys/sysctl.h>
#include <dispatch/dispatch.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_CHECK_LEAKS(false));

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(waitq_basic, "General waitq test",
    T_META_RUN_CONCURRENTLY(false))
{
	T_EXPECT_EQ(1ull, run_sysctl_test("waitq_basic", 0), "waitq_basic_test");
}

static const int NPORTS = 1024; /* must be larger than 0x200 */
static mach_port_t stress_ports[NPORTS];

T_DECL(waitq_link_alloc_stress,
    "General stress test around waitq link allocations")
{
	for (uint32_t i = 0; i < NPORTS; i++) {
		kern_return_t kr = mach_port_allocate(mach_task_self(),
		    MACH_PORT_RIGHT_RECEIVE, &stress_ports[i]);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate");
	}

	dispatch_apply(4, DISPATCH_APPLY_AUTO, ^(size_t __i __unused){
		kern_return_t kr;

		for (int times = 10; times-- > 0;) {
		        mach_port_t pset = MACH_PORT_NULL;

		        kr = mach_port_allocate(mach_task_self(),
		        MACH_PORT_RIGHT_PORT_SET, &pset);
		        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc pset");

		        for (uint32_t i = 0; i < NPORTS; i++) {
		                kr = mach_port_insert_member(mach_task_self(),
		                stress_ports[i], pset);
		                T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert_member");
			}

		        for (uint32_t i = 0; i < NPORTS; i++) {
		                kr = mach_port_move_member(mach_task_self(),
		                stress_ports[i], MACH_PORT_NULL);
		                T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert_member");
			}

		        for (uint32_t i = 0; i < NPORTS; i++) {
		                kr = mach_port_insert_member(mach_task_self(),
		                stress_ports[i], pset);
		                T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert_member");
			}

		        kr = mach_port_mod_refs(mach_task_self(), pset,
		        MACH_PORT_RIGHT_PORT_SET, -1);
		        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "dealloc pset");
		}
	});

	for (uint32_t i = 0; i < NPORTS; i++) {
		kern_return_t kr = mach_port_destruct(mach_task_self(),
		    stress_ports[i], 0, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate");
	}

	T_PASS("the kernel survived");
}
