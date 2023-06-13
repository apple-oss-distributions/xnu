#include <darwintest.h>
#include "nvram_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.nvram"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("nvram"));

static io_registry_entry_t optionsRef = IO_OBJECT_NULL;

// xcrun -sdk iphoneos.internal make -C tests nvram_var_entitled && sudo ./tests/build/sym/nvram_var_entitled

// Test that writing/deleting of entitled variables with entitlement should succeed
T_DECL(TestVarEntEntitled, "Test variable specific entitlement")
{
#if !(__x86_64__)
	const char * varToTest = "testEntitlement";

	optionsRef = GetOptions();

	T_ASSERT_EQ(SetVariable(varToTest, "1234", optionsRef), KERN_SUCCESS, "Set variable %s successfully\n", varToTest);
	T_ASSERT_EQ(DeleteVariable(varToTest, optionsRef), KERN_SUCCESS, "Deleted variable %s successfully\n", varToTest);

	ReleaseOptions(optionsRef);
#else
	T_PASS("Test not supported");
#endif /* !(__x86_64__) */
}
