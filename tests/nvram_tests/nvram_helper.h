#ifndef NVRAM_HELPER_H
#define NVRAM_HELPER_H

#include <IOKit/IOKitLib.h>

kern_return_t GetVariable(const char *name, io_registry_entry_t optionsRef);
kern_return_t SetVariable(const char *name, const char *value, io_registry_entry_t optionsRef);
kern_return_t DeleteVariable(const char *name, io_registry_entry_t optionsRef);
kern_return_t ResetNVram(io_registry_entry_t optionsRef);
io_registry_entry_t GetOptions(void);
void ReleaseOptions(io_registry_entry_t optionsRef);

#endif /* NVRAM_HELPER_H */
