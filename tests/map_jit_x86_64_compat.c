#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <darwintest.h>


/*
 * Test to verify that x86-64 emulation entitlements grant MAP_JIT access.
 * The entitlement check is enforced by AMFI (AppleMobileFileIntegrity).
 *
 * Expected behavior:
 * - With com.apple.developer.cross-architecture-support: MAP_JIT should succeed
 * - With com.apple.developer.cross-architecture-support-unmanaged: MAP_JIT should succeed
 * - Without entitlements: MAP_JIT should fail
 *
 * The EXPECT_MAP_JIT_SUCCESS macro controls expected behavior:
 * - Defined: Test passes if MAP_JIT succeeds (entitled case)
 * - Undefined: Test passes if MAP_JIT fails (unentitled case)
 */
T_DECL(map_jit_x86_64_compat, "x86-64 emulation entitlement grants MAP_JIT access")
{
#if TARGET_OS_OSX
	void *addr;
	size_t size = 64 * 1024;

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

#ifdef EXPECT_MAP_JIT_SUCCESS
	/* Entitled case: expect MAP_JIT to succeed */
	if (addr == MAP_FAILED) {
		T_FAIL("MAP_JIT failed - binary likely missing required entitlement");
	} else {
		T_PASS("MAP_JIT succeeded with x86-64 emulation entitlement");
		munmap(addr, size);
	}
#else
	/* Unentitled case: expect MAP_JIT to fail */
	if (addr == MAP_FAILED) {
		T_PASS("MAP_JIT correctly denied without entitlement");
	} else {
		T_FAIL("MAP_JIT unexpectedly succeeded without entitlement (%p)", addr);
		munmap(addr, size);
	}
#endif

#else
	T_SKIP("Not macOS");
#endif
}
