#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk iphoneos.internal make -C tests nvram_nonentitled && sudo ./tests/build/sym/nvram_nonentitled

// Test basic read, write, delete for a random variable
T_DECL(TestBasicCmds, "Test basic nvram commands")
{
	const char *varToTest = "varToTest1";

	optionsRef = GetOptions();

	T_ASSERT_EQ(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s successfully\n", varToTest);
	T_ASSERT_EQ(GetVariable(varToTest, optionsRef), KERN_SUCCESS, "Read variable %s successfully\n", varToTest);
	T_ASSERT_EQ(DeleteVariable(varToTest, optionsRef), KERN_SUCCESS, "Deleted variable %s successfully\n", varToTest);

	ReleaseOptions(optionsRef);
}

// Test basic read, write, delete for a random variable with random guid
T_DECL(TestRandomGuid, "Test random guid")
{
	const char *varToTest = "11112222-77F8-4392-B4A3-1E7304206516:varToTest3";

	optionsRef = GetOptions();

	T_ASSERT_EQ(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s successfully\n", varToTest);
	T_ASSERT_EQ(GetVariable(varToTest, optionsRef), KERN_SUCCESS, "Read variable %s successfully\n", varToTest);
	T_ASSERT_EQ(DeleteVariable(varToTest, optionsRef), KERN_SUCCESS, "Deleted variable %s successfully\n", varToTest);

	ReleaseOptions(optionsRef);
}

#if !(__x86_64__)
#if (TARGET_OS_OSX)
// Test that writing of system variables without system entitlement should fail
T_DECL(TestSystem, "Test system guids")
{
	const char *varToTest = "40A0DDD2-77F8-4392-B4A3-1E7304206516:varToTest2";

	optionsRef = GetOptions();

	T_ASSERT_NE(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s failed as expected\n", varToTest);

	ReleaseOptions(optionsRef);
}
#endif /* (TARGET_OS_OSX) */

// Test that variables with NeverAllowedToDelete bit set cannot be deleted even with ResetNVram()
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestImmutable -- -r
T_DECL(TestImmutable, "Test immutable variable")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testNeverDel";

	optionsRef = GetOptions();

	T_ASSERT_EQ(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s successfully\n", varToTest);
	T_ASSERT_NE(DeleteVariable(varToTest, optionsRef), KERN_SUCCESS, "Delete variable %s failed as expected\n", varToTest);

	if (getopt(argc, argv, "r") == 'r') {
		T_ASSERT_EQ(ResetNVram(optionsRef), KERN_SUCCESS, "Reset NVram successfully\n");
	}
	T_ASSERT_EQ(GetVariable(varToTest, optionsRef), KERN_SUCCESS, "Read variable %s successfully\n", varToTest);

	ReleaseOptions(optionsRef);
}

// Test that variables with ResetNVRAMOnlyDelete bit set can be deleted only by ResetNVram
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestResetOnlyDel -- -r
T_DECL(TestResetOnlyDel, "Test variable with ResetNVRAMOnlyDelete bit set")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testResetOnlyDel";

	optionsRef = GetOptions();

	T_ASSERT_EQ(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s successfully\n", varToTest);
	T_ASSERT_NE(DeleteVariable(varToTest, optionsRef), KERN_SUCCESS, "Delete variable %s failed as expected\n", varToTest);

	if (getopt(argc, argv, "r") == 'r') {
		T_ASSERT_EQ(ResetNVram(optionsRef), KERN_SUCCESS, "Reset NVram successfully\n");
		T_ASSERT_NE(GetVariable(varToTest, optionsRef), KERN_SUCCESS, "Read variable %s failed as expected\n", varToTest);
	}

	ReleaseOptions(optionsRef);
}

// Test that writing of entitled variables without entitlement should fail
T_DECL(TestVarEnt, "Test variable specific entitlement")
{
	const char * varToTest = "testEntitlement";

	optionsRef = GetOptions();

	T_ASSERT_NE(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s failed as expected\n", varToTest);

	ReleaseOptions(optionsRef);
}
#endif /* !(__x86_64__) */
