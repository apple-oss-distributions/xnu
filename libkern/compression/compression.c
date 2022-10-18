#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/compression/compression.h>

#if defined(SECURITY_READ_ONLY_LATE)
SECURITY_READ_ONLY_LATE(const compression_ki_t*) compression_ki_ptr = NULL;
static SECURITY_READ_ONLY_LATE(registration_callback_t) registration_callback = NULL;
#else
const compression_ki_t* compression_ki_ptr = NULL;
static registration_callback_t registration_callback = NULL;
#endif

void
compression_interface_register(const compression_ki_t *ki)
{
	if (compression_ki_ptr) {
		panic("compression interface already set");
	}

	compression_ki_ptr = ki;

	if (registration_callback) {
		registration_callback();
	}
}

void
compression_interface_set_registration_callback(registration_callback_t callback)
{
	if (callback && registration_callback) {
		panic("compression interface registration callback is already set");
	}

	registration_callback = callback;
}
