#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk macosx.internal make -C tests nvram_system && sudo ./tests/build/sym/nvram_system

// Test that writing, reading, and deleting of system variables with system entitlement should succeed
T_DECL(TestSystemEntitled, "Test system guids with entitlement")
{
#if ((TARGET_OS_OSX) && !(__x86_64__))
	const char *varToTest = "40A0DDD2-77F8-4392-B4A3-1E7304206516:varToTest2";

	optionsRef = GetOptions();

	T_ASSERT_EQ(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s successfully\n", varToTest);
	T_ASSERT_EQ(GetVariable(varToTest, optionsRef), KERN_SUCCESS, "Read variable %s successfully\n", varToTest);
	T_ASSERT_EQ(DeleteVariable(varToTest, optionsRef), KERN_SUCCESS, "Deleted variable %s successfully\n", varToTest);

	ReleaseOptions(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* ((TARGET_OS_OSX) && !(__x86_64__)) */
}
