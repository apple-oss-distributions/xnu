#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/amfi/amfi.h>

SECURITY_READ_ONLY_LATE(const amfi_t *) amfi = NULL;

void
amfi_interface_register(const amfi_t *mfi)
{
	if (amfi) {
		panic("AppleMobileFileIntegrity interface already set");
	}
	amfi = mfi;
}
