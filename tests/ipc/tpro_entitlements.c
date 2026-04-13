#include <darwintest.h>
#include <darwintest_utils.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <mach/task.h>

#import <os/security_config_private.h>     // for os_security_config_get()

#include "ipc/ipc_utils.h"
#include "task_security_config.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.spawn"),
	T_META_RUN_CONCURRENTLY(TRUE),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("spawn"),
	T_META_TAG_VM_PREFERRED);

T_DECL(test_tpro_entitlement,
    "entitlement should enable tpro configuration",
    T_META_CHECK_LEAKS(false),
    T_META_ENABLED(TARGET_CPU_ARM64E),
    T_META_BOOTARGS_SET("amfi=0x7"))
{
	struct task_security_config_info config;
	struct task_ipc_space_policy_info space_info;
	mach_msg_type_number_t count;
	kern_return_t kr;

	T_SETUPBEGIN;

	/* First things first, do nothing unless we're TPRO enabled */
	if (!(os_security_config_get() & OS_SECURITY_CONFIG_TPRO)) {
		T_SKIP("Skipping because we're not running under TPRO");
		return;
	}

	T_SETUPEND;

	count = TASK_SECURITY_CONFIG_INFO_COUNT;
	kr = task_info(mach_task_self(), TASK_SECURITY_CONFIG_INFO, (task_info_t)&config, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SECURITY_CONFIG_INFO)");
	T_ASSERT_EQ(count, 1, "security config should return 1 value");

	struct task_security_config *conf = (struct task_security_config*)&config;

	T_EXPECT_TRUE(conf->tpro, "TPRO bit should be set");

	count = TASK_IPC_SPACE_POLICY_INFO_COUNT;
	kr = task_info(mach_task_self(), TASK_IPC_SPACE_POLICY_INFO, (task_info_t)&space_info, &count);
	T_ASSERT_MACH_SUCCESS(kr, "task_info(TASK_SECURITY_CONFIG_INFO)");
	T_ASSERT_EQ_UINT(count, 1, "ipc space should return 1 value");
}
