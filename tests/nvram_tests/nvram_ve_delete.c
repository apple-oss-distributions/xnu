#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk iphoneos.internal make -C tests nvram_ve_delete && sudo ./tests/build/sym/nvram_ve_delete

// Test that deleting of entitled variables with entitlement should succeed
T_DECL(TestEntDelEnt, "Test delete entitled variables")
{
#if !(__x86_64__)
	char * varToTest = "testEntDel";

	optionsRef = CreateOptionsRef();

	TestVarOp(OP_SET, varToTest, DefaultSetVal, KERN_SUCCESS, optionsRef);
	TestVarOp(OP_DEL, varToTest, NULL, KERN_SUCCESS, optionsRef);

	ReleaseOptionsRef(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* !(__x86_64__) */
}
