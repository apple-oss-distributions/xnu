#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/apple_encrypted_archive/apple_encrypted_archive.h>

#if defined(SECURITY_READ_ONLY_LATE)
SECURITY_READ_ONLY_LATE(const apple_encrypted_archive_t *) apple_encrypted_archive = NULL;
SECURITY_READ_ONLY_LATE(registration_callback_t) registration_callback = NULL;
#else
const apple_encrypted_archive_t *apple_encrypted_archive = NULL;
registration_callback_t registration_callback = NULL;
#endif

void
apple_encrypted_archive_interface_register(const apple_encrypted_archive_t *aea)
{
	if (apple_encrypted_archive) {
		panic("apple_encrypted_archive interface already set");
	}

	apple_encrypted_archive = aea;

	if (registration_callback) {
		registration_callback();
	}
}

void
apple_encrypted_archive_interface_set_registration_callback(registration_callback_t callback)
{
	if (callback && registration_callback) {
		panic("apple_encrypted_archive interface registration callback is already set");
	}

	registration_callback = callback;
}
