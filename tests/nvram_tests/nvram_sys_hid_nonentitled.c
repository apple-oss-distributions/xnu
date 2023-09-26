#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk macosx.internal make -C tests nvram_sys_hid_nonentitled && sudo ./tests/build/sym/nvram_sys_hid_nonentitled

// Test that reading of variables with SystemReadHidden bit set without entitlement should fail
// NOTE: Test wasn't added to nvram_nonentitled.c as it requires system entitlement to set the variable
T_DECL(TestSysReadHid, "Test variable with SystemReadHidden bit set")
{
#if ((TARGET_OS_OSX) && !(__x86_64__))
	const char * varToTest = SystemNVRAMGuidString ":" "testSysReadHidden";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_GET, varToTest, NULL, KERN_FAILURE, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* ((TARGET_OS_OSX) && !(__x86_64__)) */
}
