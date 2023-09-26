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
	const char *varToTest = SystemNVRAMGuidString ":" "varToTest2";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, NULL, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* ((TARGET_OS_OSX) && !(__x86_64__)) */
}


#if !(TARGET_CPU_ARM64 && TARGET_OS_OSX)
// Test that system guid is translated to common guid on devices without system namespace support
T_DECL(TestSysNonAS, "Test system guids for devices without system namespace")
{
	const char *varWithSys = SystemNVRAMGuidString ":" "varToTestSys";
	const char *varWOSys = "varToTestSys";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varWithSys, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varWOSys, NULL, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varWOSys, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
}
#endif

// Variable entitlement tests for system variables
#if ((TARGET_OS_OSX) && !(__x86_64__))
// Test that read of entitled system variables without entitlement should fail
T_DECL(TestEntRdSys, "Test read entitled system variables")
{
	char * varToTest = SystemNVRAMGuidString ":" "testEntRdSys";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that writing of entitled system variables without entitlement should fail
T_DECL(TestEntModRstSys, "Test write entitled system variables")
{
	char * varToTest = SystemNVRAMGuidString ":" "testEntModRstSys";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, kIOReturnNotPrivileged, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test that deleting of entitled system variables without entitlement should fail
T_DECL(TestEntDelSys, "Test delete entitled system variables")
{
	char * varToTest = SystemNVRAMGuidString ":" "testEntDelSys";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_FAILURE, optionsRef);

	ReleaseOptionsRef(optionsRef);
}

// Test resetting of nvram with entitlement should not erase testEntRstSys
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_system -n xnu.nvram.TestEntRstSys -- -r
T_DECL(TestEntRstSys, "Test reset entitled system variables")
{
	opterr = 0;
	optind = 0;
	char * varToTest = SystemNVRAMGuidString ":" "testEntRstSys";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_SUCCESS, optionsRef);
	} else {
		TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}

// Test NVRAM Reset
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_system -n xnu.nvram.TestNVRAMResetSys -- -r
T_DECL(TestNVRAMResetSys, "Test NVRAM Reset for system region variables")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testVar1";
	const char * varToTestWSys = SystemNVRAMGuidString ":" "testVar2";

	optionsRef = CreateOptionsRef();

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_SET, varToTestWSys, DefaultSetVal, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);

		TestVarOp(OP_GET, varToTestWSys, NULL, KERN_FAILURE, optionsRef);
	} else {
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}

// Test NVRAM Obliterate
// To obliterate nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_system -n xnu.nvram.TestNVRAMOblitSys -- -r
T_DECL(TestNVRAMOblitSys, "Test NVRAM Obliterate for system region")
{
	opterr = 0;
	optind = 0;
	const char * varToTest = "testVar1";
	const char * varToTestWSys = SystemNVRAMGuidString ":" "testVar2";
	const char * varToTestWRand = RandomNVRAMGuidString ":" "testVar3";
	const char * oblitSys = SystemNVRAMGuidString ":" "ObliterateNVRam";
	const char * oblitNonSys = CommonNVRAMGuidString ":" "ObliterateNVRam";

	optionsRef = CreateOptionsRef();

	if (getopt(argc, argv, "r") == 'r') {
		// Set variables with common namespace, random namespace and system namespace
		TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_SET, varToTestWSys, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_SET, varToTestWRand, DefaultSetVal, KERN_SUCCESS, optionsRef);

		// Obliterate sys first and make sure non-sys variables aren't deleted
		TestVarOp(OP_OBL, oblitSys, NULL, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_GET, varToTestWSys, NULL, KERN_FAILURE, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTestWRand, NULL, KERN_SUCCESS, optionsRef);

		// Now, obliterate common region and make sure all non-sys variables are deleted
		TestVarOp(OP_SET, varToTestWSys, DefaultSetVal, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_OBL, oblitNonSys, NULL, KERN_SUCCESS, optionsRef);

		TestVarOp(OP_GET, varToTestWSys, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
		TestVarOp(OP_GET, varToTestWRand, NULL, KERN_FAILURE, optionsRef);
		TestVarOp(OP_DEL, varToTestWSys, NULL, KERN_SUCCESS, optionsRef);
	} else {
		T_PASS("NVram obliterate not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}
#endif /* ((TARGET_OS_OSX) && !(__x86_64__)) */
