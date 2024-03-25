#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include <darwintest.h>

#include "jumbo_va_spaces_common.h"

#define GB (1ULL * 1024 * 1024 * 1024)

/*
 * This test expects the entitlement to be the enabling factor for a process to
 * allocate at least this many GB of VA space. i.e. with the entitlement, n GB
 * must be allocatable; whereas without it, it must be less.
 * This value was determined experimentally to fit on applicable devices and to
 * be clearly distinguishable from the default VA limit.
 */
#define ALLOC_TEST_GB 51

void
verify_jumbo_va(bool entitled)
{
	T_LOG("Attemping to allocate VA space in 1 GB chunks.");
	void *res;
	int i;

	for (i = 0; i < (ALLOC_TEST_GB * 2); i++) {
		res = mmap(NULL, 1 * GB, PROT_NONE, MAP_PRIVATE | MAP_ANON, 0, 0);
		if (res == MAP_FAILED) {
			if (errno != ENOMEM) {
				T_WITH_ERRNO;
				T_LOG("mmap failed: stopped at %d of %d GB allocated", i, ALLOC_TEST_GB);
			}
			break;
		} else {
			T_LOG("%d: %p\n", i, res);
		}
	}

	if (entitled) {
		T_EXPECT_GE_INT(i, ALLOC_TEST_GB, "Allocate at least %d GB of VA space", ALLOC_TEST_GB);
	} else {
		T_EXPECT_LT_INT(i, ALLOC_TEST_GB, "Not permitted to allocate %d GB of VA space", ALLOC_TEST_GB);
	}
}
