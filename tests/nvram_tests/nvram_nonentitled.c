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

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test basic read, write, delete for a random variable with random guid
T_DECL(TestRandomGuid, "Test random guid")
{
	const char *varToTest = "11112222-77F8-4392-B4A3-1E7304206516:varToTest3";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test NVRAM delete with return key works
T_DECL(TestDelWRet, "Test NVRAM delete with return key")
{
	char * varToTest = "testDelWRet";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL_RET, varToTest, NULL, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test NVRAM Sync
T_DECL(TestNVRAMSync, "Test NVRAM Sync")
{
	optionsRef = CreateOptionsRef();

	// NVRAM sync using kIONVRAMSyncNowPropertyKey have a 15min rate limit.
	// However, we do not return an error for that not being able to sync due to the rate limit
	TestVarOp(OP_SYN, kIONVRAMSyncNowPropertyKey, NULL, KERN_SUCCESS, optionsRef);
	// kIONVRAMForceSyncNowPropertyKey bypasses the rate limit
	TestVarOp(OP_SYN, kIONVRAMForceSyncNowPropertyKey, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

#if !(__x86_64__)
#if (TARGET_OS_OSX)
// Test that writing of system variables without system entitlement should fail
T_DECL(TestSystem, "Test system guids")
{
	const char *varToTest = SystemNVRAMGuidString ":" "varToTest2";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, kIOReturnNotPrivileged, optionsRef);

	ReleaseOptionsRef(optionsRef);
}
#endif /* (TARGET_OS_OSX) */

// Test that writing of kernel variables without w/o kernel task should fail
T_DECL(TestKernelPrefix, "Test kernel prefix")
{
	char * varToTest = KernelOnlyVariablePrefix "kernelVar";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, kIOReturnNotPrivileged, optionsRef);

	TestVarOp(OP_GET, varToTest, DefaultSetVal, KERN_FAILURE, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that variables with KernelOnly bit set cannot be modified from user space
T_DECL(TestKernelOnly, "Test variable with TestKernelOnly bit set")
{
	char * varToTest = "testKernelOnly";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, kIOReturnNotPrivileged, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that variables with NeverAllowedToDelete bit set cannot be deleted even with ResetNVram()
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestImmutable -- -r
T_DECL(TestImmutable, "Test immutable variable")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testNeverDel";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_FAILURE, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
	}
	TestVarOp(OP_GET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that variables with ResetNVRAMOnlyDelete bit set can be deleted only by ResetNVram
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestResetOnlyDel -- -r
T_DECL(TestResetOnlyDel, "Test variable with ResetNVRAMOnlyDelete bit set")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testResetOnlyDel";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_FAILURE, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	}

	ReleaseOptionsRef(optionsRef);
}

// Test that read of entitled variables without entitlement should fail
T_DECL(TestEntRd, "Test read entitled variables")
{
	char * varToTest = "testEntRd";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that writing of entitled variables without entitlement should fail
T_DECL(TestEntModRst, "Test write entitled variables")
{
	char * varToTest = "testEntModRst";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, kIOReturnNotPrivileged, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that deleting of entitled variables without entitlement should fail
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestEntDel -- -r
T_DECL(TestEntDel, "Test delete entitled variables")
{
	opterr = 0;
	optind = 0;
	char * varToTest = "testEntDel";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_FAILURE, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	}

	ReleaseOptionsRef(optionsRef);
}

// Test resetting of nvram without entitlement should not erase TestEntRst
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestEntRst -- -r
T_DECL(TestEntRst, "Test reset entitled variables")
{
	opterr = 0;
	optind = 0;
	char * varToTest = "testEntRst";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	} else {
		TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}

// Test nvram types
T_DECL(TestTypes, "Test nvram types")
{
	char * boolVar = "test-bool";
	char * numVar  = "test-num";
	char * strVar  = "test-str";
	char * dataVar = "test-data";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, boolVar, "true", KERN_SUCCESS, optionsRef);
	TestVarOp(OP_SET, numVar, "123", KERN_SUCCESS, optionsRef);
	TestVarOp(OP_SET, strVar, "teststring", KERN_SUCCESS, optionsRef);
	TestVarOp(OP_SET, dataVar, "testdata", KERN_SUCCESS, optionsRef);

	T_ASSERT_EQ(GetVarType(boolVar, optionsRef), CFBooleanGetTypeID(), "Verified %s type as boolean.\n", boolVar);
	T_ASSERT_EQ(GetVarType(numVar, optionsRef), CFNumberGetTypeID(), "Verified %s type as number.\n", numVar);
	T_ASSERT_EQ(GetVarType(strVar, optionsRef), CFStringGetTypeID(), "Verified %s type as string.\n", strVar);
	T_ASSERT_EQ(GetVarType(dataVar, optionsRef), CFDataGetTypeID(), "Verified %s type as data.\n", dataVar);

	TestVarOp(OP_DEL, boolVar, NULL, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, numVar, NULL, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, strVar, NULL, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, dataVar, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test NVRAM Reset
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestNVRAMReset -- -r
T_DECL(TestNVRAMReset, "Test NVRAM Reset")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testVar1";
	const char * varToTestWRand = RandomNVRAMGuidString ":" "testVar2";


	optionsRef = CreateOptionsRef();

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_SET, varToTestWRand, DefaultSetVal, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
		TestVarOp(OP_GET, varToTestWRand, NULL, KERN_FAILURE, optionsRef);
	} else {
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}

// Test NVRAM Obliterate
// To obliterate nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_nonentitled -n xnu.nvram.TestNVRAMOblit -- -r
T_DECL(TestNVRAMOblit, "Test NVRAM Obliterate")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testVar1";
	const char * varToTestWRand = RandomNVRAMGuidString ":" "testVar2";
	const char * oblitNonSys = CommonNVRAMGuidString ":" "ObliterateNVRam";

	optionsRef = CreateOptionsRef();

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_SET, varToTestWRand, DefaultSetVal, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_OBL, oblitNonSys, NULL, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
		TestVarOp(OP_GET, varToTestWRand, NULL, KERN_FAILURE, optionsRef);
	} else {
		T_PASS("NVram obliterate not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}
#endif /* !(__x86_64__) */
