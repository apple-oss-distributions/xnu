#include <darwintest.h>
#include <stdint.h>
#include <bsm/libbsm.h>
#include <System/sys/codesign.h>
#include <sys/errno.h>
#include <stdio.h>
#include <unistd.h>

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

	/*
	 * Only run the folling tests if not HARD since otherwise
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
