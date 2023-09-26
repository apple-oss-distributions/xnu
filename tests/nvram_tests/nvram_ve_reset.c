#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk iphoneos.internal make -C tests nvram_ve_reset && sudo ./tests/build/sym/nvram_ve_reset

// Test resetting of nvram with entitlement should erase testEntRst
// To reset nvram, call the test with -r argument:
// sudo ./tests/build/sym/nvram_ve_reset -n xnu.nvram.TestEntRstEnt -- -r
T_DECL(TestEntRstEnt, "Test reset entitled variables")
{
#if !(__x86_64__)
	opterr = 0;
	optind = 0;
	char * varToTest = "testEntRst";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);

	if (getopt(argc, argv, "r") == 'r') {
		TestVarOp(OP_RES, NULL, NULL, KERN_SUCCESS, optionsRef);
		TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	} else {
		TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);
		T_PASS("NVram reset not invoked");
	}

	ReleaseOptionsRef(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* !(__x86_64__) */
}
