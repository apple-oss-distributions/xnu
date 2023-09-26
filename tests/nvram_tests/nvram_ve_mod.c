#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk iphoneos.internal make -C tests nvram_ve_mod && sudo ./tests/build/sym/nvram_ve_mod

// Test that writing, deleting and reseting of entitled variables with entitlement should succeed
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_ve_mod -n xnu.nvram.TestEntModRstEnt -- -r
T_DECL(TestEntModRstEnt, "Test mod of entitled variables")
{
	opterr = 0;
	optind = 0;
#if !(__x86_64__)
	char * varToTest = "testEntModRst";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	} else {
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* !(__x86_64__) */
}

#if ((TARGET_OS_OSX) && !(__x86_64__))
// Test that writing, deleting and reseting of entitled system variables with entitlement should succeed
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_ve_mod -n xnu.nvram.TestEntModRstSysEnt -- -r
T_DECL(TestEntModRstSysEnt, "Test mod of entitled system variables")
{
	opterr = 0;
	optind = 0;
	char * varToTest = SystemNVRAMGuidString ":" "testEntModRstSys";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	} else {
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
}
#endif /* ((TARGET_OS_OSX) && !(__x86_64__)) */
