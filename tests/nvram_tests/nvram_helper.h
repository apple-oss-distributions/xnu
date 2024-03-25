#ifndef NVRAM_HELPER_H
#define NVRAM_HELPER_H

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

typedef enum{
	OP_SET = 0,
	OP_GET,
	OP_DEL,
	OP_DEL_RET,
	OP_RES,
	OP_OBL,
	OP_SYN
} nvram_op;

#define SystemNVRAMGuidString "40A0DDD2-77F8-4392-B4A3-1E7304206516"
#define CommonNVRAMGuidString "7C436110-AB2A-4BBB-A880-FE41995C9F82"
#define RandomNVRAMGuidString "11112222-77F8-4392-B4A3-1E7304206516"

#define KernelOnlyVariablePrefix "krn."
#define kIONVRAMForceSyncNowPropertyKey "IONVRAM-FORCESYNCNOW-PROPERTY"
#define DefaultSetVal         "1234"

io_registry_entry_t CreateOptionsRef(void);
void ReleaseOptionsRef(io_registry_entry_t optionsRef);
void TestVarOp(nvram_op op, const char *var, const char *val, kern_return_t exp_ret, io_registry_entry_t optionsRef);
CFTypeID GetVarType(const char *name, io_registry_entry_t optionsRef);
#endif /* NVRAM_HELPER_H */
