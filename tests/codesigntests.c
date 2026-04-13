#include <darwintest.h>
#include <stdint.h>
#include <bsm/libbsm.h>
#include <System/sys/codesign.h>
#include <kern/cs_blobs.h>
#include <sys/errno.h>
#include <stdio.h>
#include <unistd.h>
#include <TargetConditionals.h>

#define MAXBUFLEN 1024 * 1024

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.codesigning"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("codesigning"),
	T_META_OWNER("rkendallkuppe"));

int
get_blob(pid_t pid, int op)
{
	uint8_t header[8];
	unsigned int cnt;
	int rcent;

	for (cnt = 0; cnt < sizeof(header); cnt++) {
		rcent = csops(pid, op, header, cnt);
		if (rcent != -1 && errno != ERANGE) {
			T_ASSERT_FAIL("errno != ERANGE for short header");
		}
	}

	rcent = csops(pid, op, header, sizeof(header));
	if (rcent == -1 && errno == ERANGE) {
		uint32_t len, bufferlen, bufferlen2;

		memcpy(&len, &header[4], 4);
		bufferlen = ntohl(len);

		T_LOG("Checking bufferlen on blob from kernel for csop %d", op);
		T_ASSERT_LE_INT(bufferlen, MAXBUFLEN, "Buffer length %zu on blob from kernel can't exceed %zu",
		    (size_t)bufferlen, MAXBUFLEN);
		T_ASSERT_NE_INT(bufferlen, 0, "Buffer length %zu on blob from kernel can't be zero",
		    (size_t)bufferlen);
		T_ASSERT_GE_INT(bufferlen, 8, "Buffer length %zu on blob from kernel can't be less than a byte",
		    (size_t)bufferlen);

		uint8_t buffer[bufferlen + 1];

		rcent = csops(pid, op, buffer, bufferlen - 1);
		T_ASSERT_POSIX_ERROR(errno, ERANGE, "Performing CS OPS csops with a full buffer - 1");

		rcent = csops(pid, op, buffer, bufferlen);
		T_ASSERT_EQ_INT(rcent, 0, "Performing CS OPS with full buffer.");

		memcpy(&len, &buffer[4], 4);
		bufferlen2 = ntohl(len);

		if (op == CS_OPS_BLOB) {
			T_ASSERT_LE_INT(bufferlen2, bufferlen, "Checking %zu is %zu larger on second try",
			    (size_t)bufferlen2, (size_t)bufferlen);

			/*
			 * CS_OPS_BLOB may want a bigger buffer than the size
			 * of the actual blob. If the blob came in through a
			 * load command for example, then CS_OPS_BLOB will
			 * want to copy out the whole buffer that the load
			 * command points to, which is usually an estimated
			 * size. The actual blob, and therefore the size in
			 * the blob's header, may be smaller.
			 */
			T_LOG("Blob is smaller (%zu) than expected (%zu). This is fine.",
			    (size_t)bufferlen2, (size_t)bufferlen);
		} else {
			T_ASSERT_EQ_INT(bufferlen2, bufferlen, "Checking bufferlen sizes are different");
		}

		rcent = csops(pid, op, buffer, bufferlen + 1);
		T_ASSERT_EQ_INT(rcent, 0, "Performing CS OPS with a full buffer + 1");

		return 0;
	} else if (rcent == 0) {
		return 0;
	} else {
		return 1;
	}
}

/*
 *  This source is compiled with different names and build flags.
 *  Makefile has the detail of the TESTNAME.
 */

T_DECL(TESTNAME, "CS OP, code sign operations test")
{
	uint32_t status;
	int rcent;
	pid_t pid;
	csops_cdhash_t cdhash_info = {0};
	uint8_t cdhash[CS_CDHASH_LEN] = {0};

	pid = getpid();

	rcent = get_blob(pid, CS_OPS_ENTITLEMENTS_BLOB);
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPS entitlements blob");

	rcent = get_blob(0, CS_OPS_ENTITLEMENTS_BLOB);
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPS entitlements blob");

	rcent = get_blob(pid, CS_OPS_BLOB);

	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPS blob");

	rcent = get_blob(0, CS_OPS_BLOB);
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPS blob");

	rcent = get_blob(pid, CS_OPS_IDENTITY);
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPs identity");

	rcent = get_blob(0, CS_OPS_IDENTITY);
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPs identity");

	rcent = csops(pid, CS_OPS_SET_STATUS, &status, sizeof(status) - 1);
	T_ASSERT_NE_INT(rcent, 0, "Checking CS OPs set status by setting buffer to (status - 1)");

	status = CS_RESTRICT;
	rcent = csops(pid, CS_OPS_SET_STATUS, &status, sizeof(status));
	T_ASSERT_EQ_INT(rcent, 0, "Checking CS OPs set status by setting proc RESTRICTED");

	rcent = csops(pid, CS_OPS_STATUS, &status, sizeof(status));
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS OPs status of process");

	rcent = csops(pid, CS_OPS_CDHASH, cdhash, sizeof(cdhash));
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS_OPS_CDHASH");

	rcent = csops(pid, CS_OPS_CDHASH_WITH_INFO, &cdhash_info, sizeof(cdhash_info));
	T_ASSERT_EQ_INT(rcent, 0, "Getting CS_OPS_CDHASH_WITH_INFO");

	/* Verify the returned CDHashes match and are the correct type */
	T_ASSERT_EQ_INT(memcmp(cdhash_info.hash, cdhash, sizeof(cdhash)), 0, "Comparing CDHashes");
	T_ASSERT_EQ_INT(cdhash_info.type, CS_HASHTYPE_SHA256, "Checking returned CDHash type [SHA256]");

	/*
	 * Only run the following tests if not HARD since otherwise
	 * we'll just die when marking ourself invalid.
	 */

	if ((status & CS_KILL) == 0) {
		rcent = csops(pid, CS_OPS_MARKINVALID, NULL, 0);
		T_ASSERT_POSIX_ZERO(rcent, 0, "Setting CS OPs mark proc invalid");

		status = CS_ENFORCEMENT;
		rcent = csops(pid, CS_OPS_SET_STATUS, &status, sizeof(status));
		T_ASSERT_POSIX_ERROR(rcent, -1, "Managed to set flags on an INVALID proc");

		rcent = get_blob(pid, CS_OPS_ENTITLEMENTS_BLOB);
		T_ASSERT_POSIX_ERROR(rcent, 1, "Got entitlements while invalid");

		rcent = get_blob(pid, CS_OPS_IDENTITY);
		T_ASSERT_POSIX_ERROR(rcent, 1, "Getting CS OPS identity");

		rcent = get_blob(0, CS_OPS_IDENTITY);
		T_ASSERT_POSIX_ERROR(rcent, 1, "Getting CS OPS identity");

		rcent = get_blob(0, CS_OPS_BLOB);
		T_ASSERT_POSIX_ERROR(rcent, 1, "Geting CS OPS blob");
	}
}

T_DECL(cs_clearinstaller_privcheck, "CS_OPS_CLEARINSTALLER privilege check (rdar://128685712)",
    T_META_ASROOT(true))
{
	int rcent;
	pid_t installer_pid, self_pid;
	uint32_t status;
	FILE *fp;

	/* Find applekeystored PID - it has CS_INSTALLER due to com.apple.rootless.install entitlement */
	fp = popen("pgrep -x applekeystored", "r");
	T_ASSERT_NOTNULL(fp, "popen to find applekeystored");

	rcent = fscanf(fp, "%d", &installer_pid);
	pclose(fp);
	T_ASSERT_EQ_INT(rcent, 1, "Found applekeystored PID");
	T_LOG("Found applekeystored at PID %d", installer_pid);

	/* Verify applekeystored has CS_INSTALLER */
	rcent = csops(installer_pid, CS_OPS_STATUS, &status, sizeof(status));
	T_ASSERT_POSIX_ZERO(rcent, "Get CS_OPS_STATUS for applekeystored");
	T_ASSERT_BITS_SET(status, CS_INSTALLER, "applekeystored has CS_INSTALLER flag");

	/* Test: Without CS_INSTALLER, we should NOT be able to clear another process's CS_INSTALLER */
	rcent = csops(installer_pid, CS_OPS_CLEARINSTALLER, NULL, 0);
	T_ASSERT_EQ_INT(rcent, -1, "Non-CS_INSTALLER process cannot clear another's CS_INSTALLER");
	T_ASSERT_EQ_INT(errno, EPERM, "Should fail with EPERM");

	/* Verify applekeystored still has CS_INSTALLER after failed attempt */
	rcent = csops(installer_pid, CS_OPS_STATUS, &status, sizeof(status));
	T_ASSERT_POSIX_ZERO(rcent, "Get CS_OPS_STATUS for applekeystored");
	T_ASSERT_BITS_SET(status, CS_INSTALLER, "applekeystored still has CS_INSTALLER flag");

	T_LOG("Successfully prevented non-CS_INSTALLER process from clearing another's CS_INSTALLER");

	/* Test: Process can always clear its own CS_INSTALLER flag (even if it doesn't have it) */
	self_pid = getpid();
	rcent = csops(self_pid, CS_OPS_CLEARINSTALLER, NULL, 0);
	T_ASSERT_POSIX_ZERO(rcent, "Process can clear its own CS_INSTALLER flag");

	T_LOG("Successfully verified process can clear its own CS_INSTALLER flag");
}
