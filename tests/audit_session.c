#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <bsm/audit.h>
#include <bsm/audit_session.h>
#include <err.h>
#include <sysexits.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>

#define RDAR_104863182

#ifndef INVALID_AUDIT_TOKEN_VALUE
#define INVALID_AUDIT_TOKEN_VALUE {{ \
	UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, \
	UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX }}
#endif

#ifndef PID_MAX
#define PID_MAX 99999
#endif

#define VALID_AU_SESSION_FLAGS ( \
	        AU_SESSION_FLAG_IS_INITIAL | \
	        AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS | \
	        AU_SESSION_FLAG_HAS_TTY | \
	        AU_SESSION_FLAG_IS_REMOTE | \
	        AU_SESSION_FLAG_HAS_CONSOLE_ACCESS | \
	        AU_SESSION_FLAG_HAS_AUTHENTICATED)

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(true),
	T_META_NAMESPACE("xnu.audit.session"));

static void
get_asid_auid(au_asid_t *asidp, au_id_t *auidp)
{
	audit_token_t token = INVALID_AUDIT_TOKEN_VALUE;
	mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
	T_ASSERT_MACH_SUCCESS(task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count), "obtain audit token for self");
	if (asidp) {
		*asidp = (au_asid_t)token.val[6];
	}
	if (auidp) {
		*auidp = (au_id_t)token.val[0];
	}
}

T_DECL(getaudit_addr, "getaudit_addr smoke test")
{
	au_asid_t asid;
	au_id_t auid;
	get_asid_auid(&asid, &auid);

	struct auditinfo_addr aia;
	int rv_from_getaudit_addr = getaudit_addr(&aia, sizeof(aia));
	if (rv_from_getaudit_addr == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for getaudit_addr(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_getaudit_addr, "getaudit_addr(2) succeeds");
	T_EXPECT_EQ(aia.ai_auid, auid, NULL);
	// any ai_mask
	// any ai_termid
	T_EXPECT_EQ(aia.ai_asid, asid, NULL);
	T_EXPECT_BITS_NOTSET(aia.ai_flags, ~(au_asflgs_t)VALID_AU_SESSION_FLAGS, NULL);
	T_EXPECT_BITS_SET(aia.ai_flags, (au_asflgs_t)AU_SESSION_FLAG_HAS_AUTHENTICATED, NULL);
}

T_DECL(getauid, "getauid smoke test")
{
	au_id_t auid;
	get_asid_auid(NULL, &auid);

	au_id_t auid2 = 666;
	int rv_from_getauid = getauid(&auid2);
	if (rv_from_getauid == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for getauid(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_getauid, "getauid(2) succeeds");
	T_EXPECT_EQ(auid2, auid, NULL);
}

T_DECL(auditon_getsflags, "auditon(A_GETSFLAGS) smoke test")
{
	au_asflgs_t flags = -1UL;
	int rv_from_auditon = auditon(A_GETSFLAGS, &flags, sizeof(flags));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_auditon, "auditon(2) A_GETSFLAGS succeeds");
	T_EXPECT_BITS_NOTSET(flags, ~(au_asflgs_t)VALID_AU_SESSION_FLAGS, NULL);
	T_EXPECT_BITS_SET(flags, (au_asflgs_t)AU_SESSION_FLAG_HAS_AUTHENTICATED, NULL);
}

T_DECL(auditon_getpinfo_addr, "auditon(A_GETPINFO_ADDR) smoke test")
{
	au_asid_t asid;
	au_id_t auid;
	get_asid_auid(&asid, &auid);

	auditpinfo_addr_t apia = {};
	apia.ap_pid = getpid();
	int rv_from_auditon = auditon(A_GETPINFO_ADDR, &apia, sizeof(apia));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_auditon, "auditon(2) A_GETPINFO_ADDR succeeds");
	T_EXPECT_EQ(apia.ap_pid, getpid(), NULL);
	T_EXPECT_EQ(apia.ap_asid, asid, NULL);
	T_EXPECT_EQ(apia.ap_auid, auid, NULL);
	// any ap_mask
	// any ap_termid
	T_EXPECT_BITS_NOTSET(apia.ap_flags, ~(au_asflgs_t)VALID_AU_SESSION_FLAGS, NULL);
	T_EXPECT_BITS_SET(apia.ap_flags, (au_asflgs_t)AU_SESSION_FLAG_HAS_AUTHENTICATED, NULL);
}

T_DECL(auditon_getsinfo_addr, "auditon(A_GETSINFO_ADDR) smoke test")
{
	au_asid_t asid;
	au_id_t auid;
	get_asid_auid(&asid, &auid);

	auditinfo_addr_t aia = {};
	aia.ai_asid = asid;
	int rv_from_auditon = auditon(A_GETSINFO_ADDR, &aia, sizeof(aia));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_auditon, "auditon(2) A_GETSINFO_ADDR succeeds");
	T_EXPECT_EQ(aia.ai_asid, asid, NULL);
	T_EXPECT_EQ(aia.ai_auid, auid, NULL);
	// any ap_mask
	// any ap_termid
	T_EXPECT_BITS_NOTSET(aia.ai_flags, ~(au_asflgs_t)VALID_AU_SESSION_FLAGS, NULL);
	T_EXPECT_BITS_SET(aia.ai_flags, (au_asflgs_t)AU_SESSION_FLAG_HAS_AUTHENTICATED, NULL);
}

T_DECL(auditon_getsinfo_addr_rootasid, "auditon(A_GETSINFO_ADDR) for root session")
{
	// asid PID_MAX + 1 is the first session created after boot, which
	// is the root session.
	au_asid_t root_asid = PID_MAX + 1; // ASSIGNED_ASID_MIN

	auditinfo_addr_t aia = {};
	aia.ai_asid = root_asid;
	int rv_from_auditon = auditon(A_GETSINFO_ADDR, &aia, sizeof(aia));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_auditon, "auditon(2) A_GETSINFO_ADDR succeeds");
	T_EXPECT_EQ(aia.ai_asid, root_asid, NULL);
	T_EXPECT_EQ(aia.ai_auid, AU_DEFAUDITID, NULL);
	// any ap_mask
	// any ap_termid
	T_EXPECT_BITS_NOTSET(aia.ai_flags, ~(au_asflgs_t)VALID_AU_SESSION_FLAGS, NULL);
	T_EXPECT_EQ(aia.ai_flags, (au_asflgs_t)AU_SESSION_FLAG_IS_INITIAL, NULL);
}

T_DECL(auditon_getsinfo_addr_asid1, "auditon(A_GETSINFO_ADDR) for asid 1")
{
	// asid 1 is in the pid range, and we don't expect launchd
	// to create a pid-based audit session for itself.
	auditinfo_addr_t aia = {};
	aia.ai_asid = 1;
	int rv_from_auditon = auditon(A_GETSINFO_ADDR, &aia, sizeof(aia));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}
	T_ASSERT_POSIX_FAILURE(rv_from_auditon, EINVAL, "auditon(2) A_GETSINFO_ADDR fails");
}

enum termid_mode {
	// Set terminal ID at session creation time.
	TERMIDM_NOUPDATE,
	// Create session w/o terminal ID, update later using setaudit_addr(2).
	TERMIDM_UPDATE_SETAUDIT_ADDR,
};

enum auid_mode {
	// Set auid at session creation time.
	AUIDM_NOUPDATE,
	// Create session w/o auid, update later using setaudit_addr(2),
	// setting the auid and updating the flags.
	AUIDM_UPDATE_SETAUDIT_ADDR,
	// Create session w/o auid, update later using setauid(2) to set the
	// auid and auditon(2) A_SETSFLAGS to update the flags.
	AUIDM_UPDATE_SETAUID,
};

// Covers many different ways to call setaudit_addr to create a
// new session and typical patterns of updating the session.
// Additionally, tests that forbidden updates to sessions are in
// fact denied.
static void
new_session_flow(au_asid_t asid, enum termid_mode termid_mode, uint32_t termid_type, enum auid_mode auid_mode)
{
	if (geteuid() != 0) {
		T_SKIP("This test should be run as super user.");
	}

	static const au_id_t test_auid_a = 555;
	static const au_id_t test_auid_b = 556;
	static const dev_t test_port = 0xDEAD;
	static const u_int32_t test_addr_a = 0x00112233;
	static const u_int32_t test_addr_b = 0x44556677;
	static const u_int32_t test_addr_c = 0x8899AABB;
	static const u_int32_t test_addr_d = 0xCCDDEEFF;
	static const unsigned int test_tmp_mask_success = 0x00003001;
	static const unsigned int test_tmp_mask_failure = 0x00003002;
	static const unsigned int test_fin_mask_success = 0x00003003;
	static const unsigned int test_fin_mask_failure = 0x00003004;

	// step 1: create new session

	struct auditinfo_addr aia1a = {}; // copy of what we pass into setaudit_addr
	struct auditinfo_addr aia1b = {}; // passed into setaudit_addr, potentially modified
	struct auditinfo_addr aia1c = {}; // obtained from getaudit_addr afterwards

	aia1a.ai_asid = asid;
	if (auid_mode == AUIDM_NOUPDATE) {
		aia1a.ai_auid = test_auid_a;
		aia1a.ai_mask.am_success = test_fin_mask_success;
		aia1a.ai_mask.am_failure = test_fin_mask_failure;
	} else {
		// AU_DEFAUDITID allows updating the auid later
		aia1a.ai_auid = AU_DEFAUDITID;
		aia1a.ai_mask.am_success = test_tmp_mask_success;
		aia1a.ai_mask.am_failure = test_tmp_mask_failure;
	}
	if (termid_mode == TERMIDM_NOUPDATE) {
		aia1a.ai_termid.at_port = test_port;
		aia1a.ai_termid.at_type = termid_type;
		aia1a.ai_termid.at_addr[0] = test_addr_a;
		if (termid_type == AU_IPv6) {
			aia1a.ai_termid.at_addr[1] = test_addr_b;
			aia1a.ai_termid.at_addr[2] = test_addr_c;
			aia1a.ai_termid.at_addr[3] = test_addr_d;
		}
	} else {
		// at_type AU_IPv4 all other fields zero allows updating ai_termid later
		aia1a.ai_termid.at_type = AU_IPv4;
	}
	// For unknown reasons, AU_SESSION_FLAG_HAS_TTY cannot be set after session creation,
	// but the terminal ID can, which seems inconsistent.
	aia1a.ai_flags = AU_SESSION_FLAG_HAS_TTY | AU_SESSION_FLAG_IS_REMOTE;
	if (auid_mode == AUIDM_NOUPDATE) {
		aia1a.ai_flags |= AU_SESSION_FLAG_HAS_AUTHENTICATED;
	}

	bcopy(&aia1a, &aia1b, sizeof(aia1b));
	int rv_from_setaudit_addr = setaudit_addr(&aia1b, sizeof(aia1b));
	if (rv_from_setaudit_addr == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for setaudit_addr(2) not available");
	}
	T_ASSERT_POSIX_SUCCESS(rv_from_setaudit_addr, "setaudit_addr(2) succeeds at creating a new session");
	if (asid == AU_ASSIGN_ASID || asid == AU_DEFAUDITSID) {
		// Kernel choses free asid above pid range
		T_EXPECT_NE(aia1b.ai_asid, AU_ASSIGN_ASID, NULL);
		T_EXPECT_NE(aia1b.ai_asid, AU_DEFAUDITSID, NULL);
		T_EXPECT_GT(aia1b.ai_asid, PID_MAX, NULL);
	} else {
		// Kernel uses our asid suggestion
		T_EXPECT_EQ(aia1b.ai_asid, aia1a.ai_asid, NULL);
	}
	T_EXPECT_EQ(aia1b.ai_auid, aia1a.ai_auid, NULL);
#ifdef RDAR_104863182
	if (asid == AU_ASSIGN_ASID || asid == AU_DEFAUDITSID) {
		// New session was copied out because of AU_ASSIGN_ASID.
		// Masks on session have been zeroed at session creation,
		// and we got the masks from the session, not the cred.
		T_EXPECT_EQ(aia1b.ai_mask.am_success, 0, NULL);
		T_EXPECT_EQ(aia1b.ai_mask.am_failure, 0, NULL);
	} else {
		// The new session was not copied out.
		// Buffer still contains the masks we passed in.
		T_EXPECT_EQ(aia1b.ai_mask.am_success, aia1a.ai_mask.am_success, NULL);
		T_EXPECT_EQ(aia1b.ai_mask.am_failure, aia1a.ai_mask.am_failure, NULL);
	}
#else // RDAR_104863182
	// A reasonable expectation would be that the mask is visible in a
	// symmetrical fashion to setaudit_addr(2) and getaudit_addr(2),
	// despite being per-process.  Otherwise the typical getaudit_addr(2)
	// then setaudit_addr(2) combo would not work as expected.
	T_EXPECT_EQ(aia1b.ai_mask.am_success, aia1a.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia1b.ai_mask.am_failure, aia1a.ai_mask.am_failure, NULL);
#endif // RDAR_104863182
	T_EXPECT_EQ(aia1b.ai_termid.at_port, aia1a.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia1b.ai_termid.at_type, aia1a.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia1b.ai_termid.at_addr[0], aia1a.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia1b.ai_termid.at_addr[1], aia1a.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia1b.ai_termid.at_addr[2], aia1a.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia1b.ai_termid.at_addr[3], aia1a.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia1b.ai_flags, aia1a.ai_flags, NULL);

	T_ASSERT_POSIX_SUCCESS(getaudit_addr(&aia1c, sizeof(aia1c)), "getaudit_addr(2) succeeds at obtaining new session aia");
	T_EXPECT_EQ(aia1c.ai_asid, aia1b.ai_asid, NULL);
	T_EXPECT_EQ(aia1c.ai_auid, aia1b.ai_auid, NULL);
#ifdef RDAR_104863182
	// Masks on session have been zeroed at session creation, and we got
	// the masks from the session back, not the cred.
	T_EXPECT_EQ(aia1c.ai_mask.am_success, 0, NULL);
	T_EXPECT_EQ(aia1c.ai_mask.am_failure, 0, NULL);
#else // RDAR_104863182
	// Expect this to match what we passed into setaudit_addr(2), or what
	// setaudit_addr(2) copied out (see reasonable expectation above).
	T_EXPECT_EQ(aia1c.ai_mask.am_success, aia1b.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia1c.ai_mask.am_failure, aia1b.ai_mask.am_failure, NULL);
#endif // RDAR_104863182
	T_EXPECT_EQ(aia1c.ai_termid.at_port, aia1b.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia1c.ai_termid.at_type, aia1b.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia1c.ai_termid.at_addr[0], aia1b.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia1c.ai_termid.at_addr[1], aia1b.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia1c.ai_termid.at_addr[2], aia1b.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia1c.ai_termid.at_addr[3], aia1b.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia1c.ai_flags, aia1b.ai_flags, NULL);

	au_asflgs_t flags1c = -1UL;
	T_ASSERT_POSIX_SUCCESS(auditon(A_GETSFLAGS, &flags1c, sizeof(flags1c)), "auditon(2) A_GETSFLAGS succeeds");
	T_EXPECT_EQ(flags1c, aia1c.ai_flags, NULL);

	// step 2: depending on termid_mode, simulate accepting a network connection

	struct auditinfo_addr aia2a = {}; // copy of what we pass into setaudit_addr
	struct auditinfo_addr aia2b = {}; // passed into setaudit_addr, potentially modified
	struct auditinfo_addr aia2c = {}; // obtained from getaudit_addr afterwards

	if (termid_mode != TERMIDM_NOUPDATE) {
		assert(termid_mode == TERMIDM_UPDATE_SETAUDIT_ADDR);

		bcopy(&aia1c, &aia2a, sizeof(aia2a));
		aia2a.ai_termid.at_port = test_port;
		aia2a.ai_termid.at_type = termid_type;
		aia2a.ai_termid.at_addr[0] = test_addr_a;
		if (termid_type == AU_IPv6) {
			aia2a.ai_termid.at_addr[1] = test_addr_b;
			aia2a.ai_termid.at_addr[2] = test_addr_c;
			aia2a.ai_termid.at_addr[3] = test_addr_d;
		}
#ifdef RDAR_104863182
		// aia1c contains the masks from the session that were zeroed at
		// session creation.  Updating the session with setaudit_addr(2)
		// will cause the masks to be updated on both the process cred
		// and the session aia itself.  To avoid losing the masks we
		// asked for at session creation, copy the masks we asked for.
		// We'd reset them to 0 otherwise.
		aia2a.ai_mask.am_success = aia1a.ai_mask.am_success;
		aia2a.ai_mask.am_failure = aia1a.ai_mask.am_failure;
#endif // RDAR_104863182

		bcopy(&aia2a, &aia2b, sizeof(aia2b));
		T_ASSERT_POSIX_SUCCESS(setaudit_addr(&aia2b, sizeof(aia2b)), "setaudit_addr(2) succeeds at updating the session with a terminal ID");
		T_EXPECT_EQ(aia2b.ai_asid, aia2a.ai_asid, NULL);
		T_EXPECT_EQ(aia2b.ai_auid, aia2a.ai_auid, NULL);
		T_EXPECT_EQ(aia2b.ai_mask.am_success, aia2a.ai_mask.am_success, NULL);
		T_EXPECT_EQ(aia2b.ai_mask.am_failure, aia2a.ai_mask.am_failure, NULL);
		T_EXPECT_EQ(aia2b.ai_termid.at_port, aia2a.ai_termid.at_port, NULL);
		T_EXPECT_EQ(aia2b.ai_termid.at_type, aia2a.ai_termid.at_type, NULL);
		T_EXPECT_EQ(aia2b.ai_termid.at_addr[0], aia2a.ai_termid.at_addr[0], NULL);
		T_EXPECT_EQ(aia2b.ai_termid.at_addr[1], aia2a.ai_termid.at_addr[1], NULL);
		T_EXPECT_EQ(aia2b.ai_termid.at_addr[2], aia2a.ai_termid.at_addr[2], NULL);
		T_EXPECT_EQ(aia2b.ai_termid.at_addr[3], aia2a.ai_termid.at_addr[3], NULL);
		T_EXPECT_EQ(aia2b.ai_flags, aia2a.ai_flags, NULL);

		T_ASSERT_POSIX_SUCCESS(getaudit_addr(&aia2c, sizeof(aia2c)), "getaudit_addr(2) succeeds at obtaining updated session aia");
		T_EXPECT_EQ(aia2c.ai_asid, aia2b.ai_asid, NULL);
		T_EXPECT_EQ(aia2c.ai_auid, aia2b.ai_auid, NULL);
		T_EXPECT_EQ(aia2c.ai_mask.am_success, aia2b.ai_mask.am_success, NULL);
		T_EXPECT_EQ(aia2c.ai_mask.am_failure, aia2b.ai_mask.am_failure, NULL);
		T_EXPECT_EQ(aia2c.ai_termid.at_port, aia2b.ai_termid.at_port, NULL);
		T_EXPECT_EQ(aia2c.ai_termid.at_type, aia2b.ai_termid.at_type, NULL);
		T_EXPECT_EQ(aia2c.ai_termid.at_addr[0], aia2b.ai_termid.at_addr[0], NULL);
		T_EXPECT_EQ(aia2c.ai_termid.at_addr[1], aia2b.ai_termid.at_addr[1], NULL);
		T_EXPECT_EQ(aia2c.ai_termid.at_addr[2], aia2b.ai_termid.at_addr[2], NULL);
		T_EXPECT_EQ(aia2c.ai_termid.at_addr[3], aia2b.ai_termid.at_addr[3], NULL);
		T_EXPECT_EQ(aia2c.ai_flags, aia2b.ai_flags, NULL);
	} else {
		assert(termid_mode == TERMIDM_NOUPDATE);

		bcopy(&aia1c, &aia2c, sizeof(aia2c));
	}

	// step 3: depending on auid_mode, simulate authenticating the session

	struct auditinfo_addr aia3a = {}; // copy of what we pass into setaudit_addr
	struct auditinfo_addr aia3b = {}; // passed into setaudit_addr, potentially modified
	struct auditinfo_addr aia3c = {}; // obtained from getaudit_addr afterwards

	if (auid_mode != AUIDM_NOUPDATE) {
		if (auid_mode == AUIDM_UPDATE_SETAUDIT_ADDR) {
			bcopy(&aia2c, &aia3a, sizeof(aia3a));
			aia3a.ai_auid = test_auid_a;
			aia3a.ai_flags |= AU_SESSION_FLAG_HAS_AUTHENTICATED;
			// Set new masks now that we know the user and would have looked
			// up the users masks using au_user_mask(3).
			aia3a.ai_mask.am_success = test_fin_mask_success;
			aia3a.ai_mask.am_failure = test_fin_mask_failure;

			bcopy(&aia3a, &aia3b, sizeof(aia3b));
			T_ASSERT_POSIX_SUCCESS(setaudit_addr(&aia3b, sizeof(aia3b)), "setaudit_addr(2) succeeds at updating the session as authenticated");
			T_EXPECT_EQ(aia3b.ai_asid, aia3a.ai_asid, NULL);
			T_EXPECT_EQ(aia3b.ai_auid, aia3a.ai_auid, NULL);
			T_EXPECT_EQ(aia3b.ai_mask.am_success, aia3a.ai_mask.am_success, NULL);
			T_EXPECT_EQ(aia3b.ai_mask.am_failure, aia3a.ai_mask.am_failure, NULL);
			T_EXPECT_EQ(aia3b.ai_termid.at_port, aia3a.ai_termid.at_port, NULL);
			T_EXPECT_EQ(aia3b.ai_termid.at_type, aia3a.ai_termid.at_type, NULL);
			T_EXPECT_EQ(aia3b.ai_termid.at_addr[0], aia3a.ai_termid.at_addr[0], NULL);
			T_EXPECT_EQ(aia3b.ai_termid.at_addr[1], aia3a.ai_termid.at_addr[1], NULL);
			T_EXPECT_EQ(aia3b.ai_termid.at_addr[2], aia3a.ai_termid.at_addr[2], NULL);
			T_EXPECT_EQ(aia3b.ai_termid.at_addr[3], aia3a.ai_termid.at_addr[3], NULL);
			T_EXPECT_EQ(aia3b.ai_flags, aia3a.ai_flags, NULL);
		} else {
			assert(auid_mode == AUIDM_UPDATE_SETAUID);

			auditpinfo_t api = {};
			api.ap_pid = getpid();
			api.ap_mask.am_success = test_fin_mask_success;
			api.ap_mask.am_failure = test_fin_mask_failure;
			T_ASSERT_POSIX_SUCCESS(auditon(A_SETPMASK, &api, sizeof(api)), "auditon(2) A_SETPMASK succeeds");

			struct auditinfo_addr new_aia = {};
			T_ASSERT_POSIX_SUCCESS(getaudit_addr(&new_aia, sizeof(new_aia)), "getaudit_addr(2) after auditon(2) A_SETPMASK succeeds");
			T_EXPECT_EQ(new_aia.ai_asid, aia2c.ai_asid, NULL);
			T_EXPECT_EQ(new_aia.ai_auid, aia2c.ai_auid, NULL);
#ifdef RDAR_104863182
			// auditon(A_SETPMASK) sets the new masks only on process credential,
			// because audit_session_setaia() only copies the aia to the session
			// when fields other than only the masks have changed.
			// The call to setauid(2) below will propagate the masks from the
			// process credential to the audit session, from where it will be
			// visible to getaudit_addr(2).
			T_EXPECT_EQ(new_aia.ai_mask.am_success, aia2c.ai_mask.am_success, NULL);
			T_EXPECT_EQ(new_aia.ai_mask.am_failure, aia2c.ai_mask.am_failure, NULL);
#else
			// Expect the per-process mask to be visible to getaudit_addr(2).
			T_EXPECT_EQ(new_aia.ai_mask.am_success, test_fin_mask_success, NULL);
			T_EXPECT_EQ(new_aia.ai_mask.am_failure, test_fin_mask_failure, NULL);
#endif
			T_EXPECT_EQ(new_aia.ai_termid.at_port, aia2c.ai_termid.at_port, NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_type, aia2c.ai_termid.at_type, NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[0], aia2c.ai_termid.at_addr[0], NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[1], aia2c.ai_termid.at_addr[1], NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[2], aia2c.ai_termid.at_addr[2], NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[3], aia2c.ai_termid.at_addr[3], NULL);
			T_EXPECT_EQ(new_aia.ai_flags, aia2c.ai_flags, NULL);

			au_id_t new_auid = test_auid_a;
			T_ASSERT_POSIX_SUCCESS(setauid(&new_auid), "setauid(2) succeeds at updating the auid of the session");
			T_EXPECT_EQ(new_auid, test_auid_a, NULL);

			T_ASSERT_POSIX_SUCCESS(getaudit_addr(&new_aia, sizeof(new_aia)), "getaudit_addr(2) after setauid(2) succeeds");
			T_EXPECT_EQ(new_aia.ai_asid, aia2c.ai_asid, NULL);
			T_EXPECT_EQ(new_aia.ai_auid, new_auid, NULL);
			T_EXPECT_EQ(new_aia.ai_mask.am_success, test_fin_mask_success, NULL);
			T_EXPECT_EQ(new_aia.ai_mask.am_failure, test_fin_mask_failure, NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_port, aia2c.ai_termid.at_port, NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_type, aia2c.ai_termid.at_type, NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[0], aia2c.ai_termid.at_addr[0], NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[1], aia2c.ai_termid.at_addr[1], NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[2], aia2c.ai_termid.at_addr[2], NULL);
			T_EXPECT_EQ(new_aia.ai_termid.at_addr[3], aia2c.ai_termid.at_addr[3], NULL);
			T_EXPECT_EQ(new_aia.ai_flags, aia2c.ai_flags, NULL);

			// propagates masks from audit session to process credential
			au_asflgs_t new_flags = -1UL;
			T_ASSERT_POSIX_SUCCESS(auditon(A_GETSFLAGS, &new_flags, sizeof(new_flags)), "auditon(2) A_GETSFLAGS succeeds");
			T_EXPECT_EQ(new_flags, flags1c, NULL);
			new_flags |= AU_SESSION_FLAG_HAS_AUTHENTICATED;
			T_ASSERT_POSIX_SUCCESS(auditon(A_SETSFLAGS, &new_flags, sizeof(new_flags)), "auditon(2) A_SETSFLAGS succeeds");
			T_EXPECT_EQ(new_flags, flags1c | AU_SESSION_FLAG_HAS_AUTHENTICATED, NULL);
			new_flags = -1UL;
			T_ASSERT_POSIX_SUCCESS(auditon(A_GETSFLAGS, &new_flags, sizeof(new_flags)), "auditon(2) A_GETSFLAGS succeeds");
			T_EXPECT_EQ(new_flags, flags1c | AU_SESSION_FLAG_HAS_AUTHENTICATED, NULL);

			bcopy(&aia2c, &aia3b, sizeof(aia3b));
			aia3b.ai_auid = new_auid;
			aia3b.ai_flags |= AU_SESSION_FLAG_HAS_AUTHENTICATED;
			aia3b.ai_mask.am_success = test_fin_mask_success;
			aia3b.ai_mask.am_failure = test_fin_mask_failure;
		}

		T_ASSERT_POSIX_SUCCESS(getaudit_addr(&aia3c, sizeof(aia3c)), "getaudit_addr(2) succeeds at obtaining updated session aia");
		T_EXPECT_EQ(aia3c.ai_asid, aia3b.ai_asid, NULL);
		T_EXPECT_EQ(aia3c.ai_auid, aia3b.ai_auid, NULL);
		T_EXPECT_EQ(aia3c.ai_mask.am_success, aia3b.ai_mask.am_success, NULL);
		T_EXPECT_EQ(aia3c.ai_mask.am_failure, aia3b.ai_mask.am_failure, NULL);
		T_EXPECT_EQ(aia3c.ai_termid.at_port, aia3b.ai_termid.at_port, NULL);
		T_EXPECT_EQ(aia3c.ai_termid.at_type, aia3b.ai_termid.at_type, NULL);
		T_EXPECT_EQ(aia3c.ai_termid.at_addr[0], aia3b.ai_termid.at_addr[0], NULL);
		T_EXPECT_EQ(aia3c.ai_termid.at_addr[1], aia3b.ai_termid.at_addr[1], NULL);
		T_EXPECT_EQ(aia3c.ai_termid.at_addr[2], aia3b.ai_termid.at_addr[2], NULL);
		T_EXPECT_EQ(aia3c.ai_termid.at_addr[3], aia3b.ai_termid.at_addr[3], NULL);
		T_EXPECT_EQ(aia3c.ai_flags, aia3b.ai_flags, NULL);
	} else {
		assert(auid_mode == AUIDM_NOUPDATE);

		bcopy(&aia2c, &aia3c, sizeof(aia3c));
	}

	// At this point, the session is fully set up.

	// Changing the auid after it has been set is forbidden.

	struct auditinfo_addr aia4a = {};
	bcopy(&aia3c, &aia4a, sizeof(aia4a));
	aia4a.ai_auid = test_auid_b;
	struct auditinfo_addr aia4b = {};
	bcopy(&aia4a, &aia4b, sizeof(aia4b));
	T_ASSERT_POSIX_FAILURE(setaudit_addr(&aia4b, sizeof(aia4b)), EINVAL, "setaudit_addr(2) refuses changing auid once set");
	T_EXPECT_EQ(aia4b.ai_asid, aia4a.ai_asid, NULL);
	T_EXPECT_EQ(aia4b.ai_auid, aia4a.ai_auid, NULL);
	T_EXPECT_EQ(aia4b.ai_mask.am_success, aia4a.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia4b.ai_mask.am_failure, aia4a.ai_mask.am_failure, NULL);
	T_EXPECT_EQ(aia4b.ai_termid.at_port, aia4a.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia4b.ai_termid.at_type, aia4a.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia4b.ai_termid.at_addr[0], aia4a.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia4b.ai_termid.at_addr[1], aia4a.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia4b.ai_termid.at_addr[2], aia4a.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia4b.ai_termid.at_addr[3], aia4a.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia4b.ai_flags, aia4a.ai_flags, NULL);

	au_id_t new_auid = test_auid_b;
	T_ASSERT_POSIX_FAILURE(setauid(&new_auid), EINVAL, "setauid(2) refuses changing auid once set");
	T_EXPECT_EQ(new_auid, test_auid_b, NULL);

	// Changing the terminal ID after it has been set is forbidden.

	struct auditinfo_addr aia5a = {};
	bcopy(&aia3c, &aia5a, sizeof(aia5a));
	aia5a.ai_termid.at_port = ~aia5a.ai_termid.at_port;
	struct auditinfo_addr aia5b = {};
	bcopy(&aia5a, &aia5b, sizeof(aia5b));
	T_ASSERT_POSIX_FAILURE(setaudit_addr(&aia5b, sizeof(aia5b)), EINVAL, "setaudit_addr(2) refuses changing termid port once set");
	T_EXPECT_EQ(aia5b.ai_asid, aia5a.ai_asid, NULL);
	T_EXPECT_EQ(aia5b.ai_auid, aia5a.ai_auid, NULL);
	T_EXPECT_EQ(aia5b.ai_mask.am_success, aia5a.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia5b.ai_mask.am_failure, aia5a.ai_mask.am_failure, NULL);
	T_EXPECT_EQ(aia5b.ai_termid.at_port, aia5a.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia5b.ai_termid.at_type, aia5a.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia5b.ai_termid.at_addr[0], aia5a.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia5b.ai_termid.at_addr[1], aia5a.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia5b.ai_termid.at_addr[2], aia5a.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia5b.ai_termid.at_addr[3], aia5a.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia5b.ai_flags, aia5a.ai_flags, NULL);

	struct auditinfo_addr aia6a = {};
	bcopy(&aia3c, &aia6a, sizeof(aia6a));
	aia6a.ai_termid.at_type = aia6a.ai_termid.at_type == AU_IPv4 ? AU_IPv6 : AU_IPv4;
	struct auditinfo_addr aia6b = {};
	bcopy(&aia6a, &aia6b, sizeof(aia6b));
	T_ASSERT_POSIX_FAILURE(setaudit_addr(&aia6b, sizeof(aia6b)), EINVAL, "setaudit_addr(2) refuses changing termid type once set");
	T_EXPECT_EQ(aia6b.ai_asid, aia6a.ai_asid, NULL);
	T_EXPECT_EQ(aia6b.ai_auid, aia6a.ai_auid, NULL);
	T_EXPECT_EQ(aia6b.ai_mask.am_success, aia6a.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia6b.ai_mask.am_failure, aia6a.ai_mask.am_failure, NULL);
	T_EXPECT_EQ(aia6b.ai_termid.at_port, aia6a.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia6b.ai_termid.at_type, aia6a.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia6b.ai_termid.at_addr[0], aia6a.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia6b.ai_termid.at_addr[1], aia6a.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia6b.ai_termid.at_addr[2], aia6a.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia6b.ai_termid.at_addr[3], aia6a.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia6b.ai_flags, aia6a.ai_flags, NULL);

	struct auditinfo_addr aia7a = {};
	bcopy(&aia3c, &aia7a, sizeof(aia7a));
	aia7a.ai_termid.at_addr[0] = ~aia7a.ai_termid.at_addr[0];
	struct auditinfo_addr aia7b = {};
	bcopy(&aia7a, &aia7b, sizeof(aia7b));
	T_ASSERT_POSIX_FAILURE(setaudit_addr(&aia7b, sizeof(aia7b)), EINVAL, "setaudit_addr(2) refuses changing termid addr once set");
	T_EXPECT_EQ(aia7b.ai_asid, aia7a.ai_asid, NULL);
	T_EXPECT_EQ(aia7b.ai_auid, aia7a.ai_auid, NULL);
	T_EXPECT_EQ(aia7b.ai_mask.am_success, aia7a.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia7b.ai_mask.am_failure, aia7a.ai_mask.am_failure, NULL);
	T_EXPECT_EQ(aia7b.ai_termid.at_port, aia7a.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia7b.ai_termid.at_type, aia7a.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia7b.ai_termid.at_addr[0], aia7a.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia7b.ai_termid.at_addr[1], aia7a.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia7b.ai_termid.at_addr[2], aia7a.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia7b.ai_termid.at_addr[3], aia7a.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia7b.ai_flags, aia7a.ai_flags, NULL);

	// Removing protected flags is forbidden.

	struct auditinfo_addr aia8a = {};
	bcopy(&aia3c, &aia8a, sizeof(aia8a));
	aia8a.ai_flags &= ~(au_asflgs_t)AU_SESSION_FLAG_IS_REMOTE;
	struct auditinfo_addr aia8b = {};
	bcopy(&aia8a, &aia8b, sizeof(aia8b));
	T_ASSERT_POSIX_FAILURE(setaudit_addr(&aia8b, sizeof(aia8b)), EINVAL, "setaudit_addr(2) refuses changing protected flags once set");
	T_EXPECT_EQ(aia8b.ai_asid, aia8a.ai_asid, NULL);
	T_EXPECT_EQ(aia8b.ai_auid, aia8a.ai_auid, NULL);
	T_EXPECT_EQ(aia8b.ai_mask.am_success, aia8a.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia8b.ai_mask.am_failure, aia8a.ai_mask.am_failure, NULL);
	T_EXPECT_EQ(aia8b.ai_termid.at_port, aia8a.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia8b.ai_termid.at_type, aia8a.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia8b.ai_termid.at_addr[0], aia8a.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia8b.ai_termid.at_addr[1], aia8a.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia8b.ai_termid.at_addr[2], aia8a.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia8b.ai_termid.at_addr[3], aia8a.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia8b.ai_flags, aia8a.ai_flags, NULL);

	au_asflgs_t new_flags = -1UL;
	T_ASSERT_POSIX_SUCCESS(auditon(A_GETSFLAGS, &new_flags, sizeof(new_flags)), "auditon(2) A_GETSFLAGS succeeds");
	T_EXPECT_BITS_SET(new_flags, AU_SESSION_FLAG_IS_REMOTE, NULL);
	new_flags &= ~(au_asflgs_t)AU_SESSION_FLAG_IS_REMOTE;
	T_ASSERT_POSIX_FAILURE(auditon(A_SETSFLAGS, &new_flags, sizeof(new_flags)), EINVAL, "auditon(2) A_SETSFLAGS refuses changing protected flags once set");
	T_EXPECT_BITS_NOTSET(new_flags, AU_SESSION_FLAG_IS_REMOTE, NULL);

	// auditon(2) A_GETPINFO retrieves the session by pid, IPv4 only.

	auditpinfo_t api = {};
	api.ap_pid = getpid();
	if (termid_type == AU_IPv4) {
		T_ASSERT_POSIX_SUCCESS(auditon(A_GETPINFO, &api, sizeof(api)), "auditon(2) A_GETPINFO succeeds for IPv4 terminal ID");
		T_EXPECT_EQ(api.ap_pid, getpid(), NULL);
		T_EXPECT_EQ(api.ap_asid, aia3c.ai_asid, NULL);
		T_EXPECT_EQ(api.ap_auid, aia3c.ai_auid, NULL);
		T_EXPECT_EQ(api.ap_mask.am_success, test_fin_mask_success, NULL);
		T_EXPECT_EQ(api.ap_mask.am_failure, test_fin_mask_failure, NULL);
		T_EXPECT_EQ(api.ap_termid.port, aia3c.ai_termid.at_port, NULL);
		T_EXPECT_EQ(api.ap_termid.machine, aia3c.ai_termid.at_addr[0], NULL);
	} else {
		T_ASSERT_POSIX_FAILURE(auditon(A_GETPINFO, &api, sizeof(api)), EINVAL, "auditon(2) A_GETPINFO fails for IPv6 terminal ID");
	}

	// auditon(2) A_GETPINFO_ADDR retrieves the session by pid.

	auditpinfo_addr_t apia = {};
	apia.ap_pid = getpid();
	T_ASSERT_POSIX_SUCCESS(auditon(A_GETPINFO_ADDR, &apia, sizeof(apia)), "auditon(2) A_GETPINFO_ADDR succeeds");
	T_EXPECT_EQ(apia.ap_pid, getpid(), NULL);
	T_EXPECT_EQ(apia.ap_asid, aia3c.ai_asid, NULL);
	T_EXPECT_EQ(apia.ap_auid, aia3c.ai_auid, NULL);
	T_EXPECT_EQ(apia.ap_mask.am_success, test_fin_mask_success, NULL);
	T_EXPECT_EQ(apia.ap_mask.am_failure, test_fin_mask_failure, NULL);
	T_EXPECT_EQ(apia.ap_termid.at_port, aia3c.ai_termid.at_port, NULL);
	T_EXPECT_EQ(apia.ap_termid.at_type, aia3c.ai_termid.at_type, NULL);
	T_EXPECT_EQ(apia.ap_termid.at_addr[0], aia3c.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(apia.ap_termid.at_addr[1], aia3c.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(apia.ap_termid.at_addr[2], aia3c.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(apia.ap_termid.at_addr[3], aia3c.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(apia.ap_flags, aia3c.ai_flags, NULL);

	// auditon(2) A_GETSINFO_ADDR retrieves the session by asid.

	auditinfo_addr_t aia9 = {};
	aia9.ai_asid = aia3c.ai_asid;
	T_ASSERT_POSIX_SUCCESS(auditon(A_GETSINFO_ADDR, &aia9, sizeof(aia9)), "auditon(2) A_GETSINFO_ADDR succeeds");
	T_EXPECT_EQ(aia9.ai_asid, aia3c.ai_asid, NULL);
	T_EXPECT_EQ(aia9.ai_auid, aia3c.ai_auid, NULL);
#ifdef RDAR_104863182
	if (termid_mode == TERMIDM_NOUPDATE && auid_mode == AUIDM_NOUPDATE) {
		// Session still has the initial 0 masks from session creation
		T_EXPECT_EQ(aia9.ai_mask.am_success, 0, NULL);
		T_EXPECT_EQ(aia9.ai_mask.am_failure, 0, NULL);
	} else {
		// Session masks got overwritten by a session update
		T_EXPECT_EQ(aia9.ai_mask.am_success, test_fin_mask_success, NULL);
		T_EXPECT_EQ(aia9.ai_mask.am_failure, test_fin_mask_failure, NULL);
	}
#else // RDAR_104863182
	// Session masks should still be zero unless clobbered by audit session Mach port creation
	T_EXPECT_EQ(aia9.ai_mask.am_success, 0, NULL);
	T_EXPECT_EQ(aia9.ai_mask.am_failure, 0, NULL);
#endif // RDAR_104863182
	T_EXPECT_EQ(aia9.ai_termid.at_port, aia3c.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia9.ai_termid.at_type, aia3c.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia9.ai_termid.at_addr[0], aia3c.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia9.ai_termid.at_addr[1], aia3c.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia9.ai_termid.at_addr[2], aia3c.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia9.ai_termid.at_addr[3], aia3c.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia9.ai_flags, aia3c.ai_flags, NULL);
}

// Test all combinations of:
// asid = { AU_ASSIGN_ASID | AU_DEFAUDITSID | getpid() }
// termid_mode = { TERMIDM_NOUPDATE | TERMIDM_UPDATE_SETAUDIT_ADDR }
// termid_type = { AU_IPv4 | AU_IPv6 }
// auid_mode = { AUIDM_NOUPDATE | AUIDM_UPDATE_SETAUDIT_ADDR | AUIDM_UPDATE_SETAUID }

T_DECL(new_session_1141, "new session asid=AU_ASSIGN_ASID termid=noupdate IPv4 auid=noupdate")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_NOUPDATE, AU_IPv4, AUIDM_NOUPDATE);
}

T_DECL(new_session_1142, "new session asid=AU_ASSIGN_ASID termid=noupdate IPv4 auid=setaudit_addr")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_NOUPDATE, AU_IPv4, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_1143, "new session asid=AU_ASSIGN_ASID termid=noupdate IPv4 auid=setauid")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_NOUPDATE, AU_IPv4, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_1161, "new session asid=AU_ASSIGN_ASID termid=noupdate IPv6 auid=noupdate")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_NOUPDATE, AU_IPv6, AUIDM_NOUPDATE);
}

T_DECL(new_session_1162, "new session asid=AU_ASSIGN_ASID termid=noupdate IPv6 auid=setaudit_addr")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_NOUPDATE, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_1163, "new session asid=AU_ASSIGN_ASID termid=noupdate IPv6 auid=setauid")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_NOUPDATE, AU_IPv6, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_1241, "new session asid=AU_ASSIGN_ASID termid=setaudit_addr IPv4 auid=noupdate")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_NOUPDATE);
}

T_DECL(new_session_1242, "new session asid=AU_ASSIGN_ASID termid=setaudit_addr IPv4 auid=setaudit_addr")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_1243, "new session asid=AU_ASSIGN_ASID termid=setaudit_addr IPv4 auid=setauid")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_1261, "new session asid=AU_ASSIGN_ASID termid=setaudit_addr IPv6 auid=noupdate")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_NOUPDATE);
}

T_DECL(new_session_1262, "new session asid=AU_ASSIGN_ASID termid=setaudit_addr IPv6 auid=setaudit_addr")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_1263, "new session asid=AU_ASSIGN_ASID termid=setaudit_addr IPv6 auid=setauid")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_2141, "new session asid=AU_DEFAUDITSID termid=noupdate IPv4 auid=noupdate")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_NOUPDATE, AU_IPv4, AUIDM_NOUPDATE);
}

T_DECL(new_session_2142, "new session asid=AU_DEFAUDITSID termid=noupdate IPv4 auid=setaudit_addr")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_NOUPDATE, AU_IPv4, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_2143, "new session asid=AU_DEFAUDITSID termid=noupdate IPv4 auid=setauid")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_NOUPDATE, AU_IPv4, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_2161, "new session asid=AU_DEFAUDITSID termid=noupdate IPv6 auid=noupdate")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_NOUPDATE, AU_IPv6, AUIDM_NOUPDATE);
}

T_DECL(new_session_2162, "new session asid=AU_DEFAUDITSID termid=noupdate IPv6 auid=setaudit_addr")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_NOUPDATE, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_2163, "new session asid=AU_DEFAUDITSID termid=noupdate IPv6 auid=setauid")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_NOUPDATE, AU_IPv6, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_2241, "new session asid=AU_DEFAUDITSID termid=setaudit_addr IPv4 auid=noupdate")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_NOUPDATE);
}

T_DECL(new_session_2242, "new session asid=AU_DEFAUDITSID termid=setaudit_addr IPv4 auid=setaudit_addr")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_2243, "new session asid=AU_DEFAUDITSID termid=setaudit_addr IPv4 auid=setauid")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_2261, "new session asid=AU_DEFAUDITSID termid=setaudit_addr IPv6 auid=noupdate")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_NOUPDATE);
}

T_DECL(new_session_2262, "new session asid=AU_DEFAUDITSID termid=setaudit_addr IPv6 auid=setaudit_addr")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_2263, "new session asid=AU_DEFAUDITSID termid=setaudit_addr IPv6 auid=setauid")
{
	new_session_flow(AU_DEFAUDITSID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_3141, "new session asid=getpid() termid=noupdate IPv4 auid=noupdate")
{
	new_session_flow(getpid(), TERMIDM_NOUPDATE, AU_IPv4, AUIDM_NOUPDATE);
}

T_DECL(new_session_3142, "new session asid=getpid() termid=noupdate IPv4 auid=setaudit_addr")
{
	new_session_flow(getpid(), TERMIDM_NOUPDATE, AU_IPv4, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_3143, "new session asid=getpid() termid=noupdate IPv4 auid=setauid")
{
	new_session_flow(getpid(), TERMIDM_NOUPDATE, AU_IPv4, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_3161, "new session asid=getpid() termid=noupdate IPv6 auid=noupdate")
{
	new_session_flow(getpid(), TERMIDM_NOUPDATE, AU_IPv6, AUIDM_NOUPDATE);
}

T_DECL(new_session_3162, "new session asid=getpid() termid=noupdate IPv6 auid=setaudit_addr")
{
	new_session_flow(getpid(), TERMIDM_NOUPDATE, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_3163, "new session asid=getpid() termid=noupdate IPv6 auid=setauid")
{
	new_session_flow(getpid(), TERMIDM_NOUPDATE, AU_IPv6, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_3241, "new session asid=getpid() termid=setaudit_addr IPv4 auid=noupdate")
{
	new_session_flow(getpid(), TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_NOUPDATE);
}

T_DECL(new_session_3242, "new session asid=getpid() termid=setaudit_addr IPv4 auid=setaudit_addr")
{
	new_session_flow(getpid(), TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_3243, "new session asid=getpid() termid=setaudit_addr IPv4 auid=setauid")
{
	new_session_flow(getpid(), TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv4, AUIDM_UPDATE_SETAUID);
}

T_DECL(new_session_3261, "new session asid=getpid() termid=setaudit_addr IPv6 auid=noupdate")
{
	new_session_flow(getpid(), TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_NOUPDATE);
}

T_DECL(new_session_3262, "new session asid=getpid() termid=setaudit_addr IPv6 auid=setaudit_addr")
{
	new_session_flow(getpid(), TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);
}

T_DECL(new_session_3263, "new session asid=getpid() termid=setaudit_addr IPv6 auid=setauid")
{
	new_session_flow(getpid(), TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUID);
}

#define NEW_SESSION_CHECK_CHILD_FILENAME "new_session_check_child_aia"

T_HELPER_DECL(check_child_session, "Check child aia against file")
{
	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "%s/" NEW_SESSION_CHECK_CHILD_FILENAME, dt_tmpdir());
	int fd = open(path, O_RDONLY);
	T_ASSERT_POSIX_SUCCESS(fd, "open %s by pid %d for reading", path, getpid());
	struct auditinfo_addr expected_aia;
	ssize_t bytes_read = read(fd, &expected_aia, sizeof(expected_aia));
	T_ASSERT_EQ(bytes_read, (ssize_t)sizeof(expected_aia), NULL);
	close(fd);

	struct auditinfo_addr aia;
	T_ASSERT_POSIX_SUCCESS(getaudit_addr(&aia, sizeof(aia)), "getaudit_addr(2) succeeds");
	T_EXPECT_EQ(aia.ai_asid, expected_aia.ai_asid, NULL);
	T_EXPECT_EQ(aia.ai_auid, expected_aia.ai_auid, NULL);
	T_EXPECT_EQ(aia.ai_mask.am_success, expected_aia.ai_mask.am_success, NULL);
	T_EXPECT_EQ(aia.ai_mask.am_failure, expected_aia.ai_mask.am_failure, NULL);
	T_EXPECT_EQ(aia.ai_termid.at_port, expected_aia.ai_termid.at_port, NULL);
	T_EXPECT_EQ(aia.ai_termid.at_type, expected_aia.ai_termid.at_type, NULL);
	T_EXPECT_EQ(aia.ai_termid.at_addr[0], expected_aia.ai_termid.at_addr[0], NULL);
	T_EXPECT_EQ(aia.ai_termid.at_addr[1], expected_aia.ai_termid.at_addr[1], NULL);
	T_EXPECT_EQ(aia.ai_termid.at_addr[2], expected_aia.ai_termid.at_addr[2], NULL);
	T_EXPECT_EQ(aia.ai_termid.at_addr[3], expected_aia.ai_termid.at_addr[3], NULL);
	T_EXPECT_EQ(aia.ai_flags, expected_aia.ai_flags, NULL);

	T_END;
}

T_DECL(new_session_check_child_aia, "new session is inherited by child processes")
{
	int cond, rv_from_auditon = auditon(A_GETCOND, &cond, sizeof(cond));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}

	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);

	struct auditinfo_addr aia;
	T_ASSERT_POSIX_SUCCESS(getaudit_addr(&aia, sizeof(aia)), "getaudit_addr(2) succeeds");

	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "%s/" NEW_SESSION_CHECK_CHILD_FILENAME, dt_tmpdir());
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0755);
	T_ASSERT_POSIX_SUCCESS(fd, "open %s by pid %d for writing", path, getpid());
	ssize_t bytes_written = write(fd, &aia, sizeof(aia));
	T_ASSERT_EQ(bytes_written, (ssize_t)sizeof(aia), NULL);
	close(fd);

	dt_helper_t helper = dt_child_helper("check_child_session");
	dt_run_helpers(&helper, 1, 30 /* timeout */);
}

#undef NEW_SESSION_CHECK_CHILD_FILENAME

#define NEW_SESSION_CLEANUP_FILENAME "new_session_cleanup_aia"

T_HELPER_DECL(child_create_session, "Create a session in a child process")
{
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);

	struct auditinfo_addr aia;
	T_ASSERT_POSIX_SUCCESS(getaudit_addr(&aia, sizeof(aia)), "getaudit_addr(2) succeeds");

	char tmppath[MAXPATHLEN];
	snprintf(tmppath, MAXPATHLEN, "%s/" NEW_SESSION_CLEANUP_FILENAME "~", dt_tmpdir());
	int fd = open(tmppath, O_CREAT | O_TRUNC | O_RDWR, 0755);
	T_ASSERT_POSIX_SUCCESS(fd, "open %s by pid %d for writing", tmppath, getpid());
	ssize_t bytes_written = write(fd, &aia, sizeof(aia));
	T_ASSERT_EQ(bytes_written, (ssize_t)sizeof(aia), NULL);
	pid_t pid = getpid();
	bytes_written = write(fd, &pid, sizeof(pid));
	T_ASSERT_EQ(bytes_written, (ssize_t)sizeof(pid), NULL);
	close(fd);

	// Atomically move it into place so that we can reliably for it over in the other helper.
	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "%s/" NEW_SESSION_CLEANUP_FILENAME, dt_tmpdir());
	T_ASSERT_POSIX_SUCCESS(rename(tmppath, path), "move %s to %s by pid %d", tmppath, path, getpid());

	T_END;
}

T_HELPER_DECL(child_session_disappeared, "Check that session created in other helper disappeared")
{
	static const size_t max_attempts = 10;
	static const useconds_t delay_us = 250000;

	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "%s/" NEW_SESSION_CLEANUP_FILENAME, dt_tmpdir());

	// Wait for the file written by the other helper.
	int fd = -1;
	for (size_t attempt = 0; fd == -1 && attempt < max_attempts; attempt++) {
		if (attempt > 0) {
			usleep(delay_us * (useconds_t)attempt);
		}
		fd = open(path, O_RDONLY);
	}
	T_ASSERT_POSIX_SUCCESS(fd, "open %s by pid %d for reading", path, getpid());
	struct auditinfo_addr other_child_aia;
	ssize_t bytes_read = read(fd, &other_child_aia, sizeof(other_child_aia));
	T_ASSERT_EQ(bytes_read, (ssize_t)sizeof(other_child_aia), NULL);
	pid_t other_child_pid;
	bytes_read = read(fd, &other_child_pid, sizeof(other_child_pid));
	T_ASSERT_EQ(bytes_read, (ssize_t)sizeof(other_child_pid), NULL);
	close(fd);

	// Wait for the other helper to have exited.
	int rv = 0;
	for (size_t attempt = 0; rv == 0 && attempt < max_attempts; attempt++) {
		if (attempt > 0) {
			usleep(delay_us * (useconds_t)attempt);
		}
		rv = kill(other_child_pid, 0);
	}

	// The session should now have disappeared.
	auditinfo_addr_t aia = {};
	aia.ai_asid = other_child_aia.ai_asid;
	T_ASSERT_POSIX_FAILURE(auditon(A_GETSINFO_ADDR, &aia, sizeof(aia)), EINVAL, "auditon(2) A_GETSINFO_ADDR cannot find the session");

	T_END;
}

T_DECL(new_session_cleanup, "new session disappears on process exit")
{
	int cond, rv_from_auditon = auditon(A_GETCOND, &cond, sizeof(cond));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}

	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "%s/" NEW_SESSION_CLEANUP_FILENAME, dt_tmpdir());
	(void)unlink(path);

	dt_helper_t helpers[2];
	helpers[0] = dt_child_helper("child_create_session");
	helpers[1] = dt_child_helper("child_session_disappeared");
	dt_run_helpers(helpers, 2, 30 /* timeout */);
}

#undef NEW_SESSION_CLEANUP_FILENAME

T_DECL(audit_session_self, "audit_session_self(2) smoke test")
{
	int cond, rv_from_auditon = auditon(A_GETCOND, &cond, sizeof(cond));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}

	mach_port_t session_port = audit_session_self();
	T_ASSERT_TRUE(MACH_PORT_VALID(session_port), "audit_session_self(2) returns valid send right");
}

T_DECL(audit_session_port_join, "audit_session_port(2) and audit_session_join(2) smoke test")
{
	int cond, rv_from_auditon = auditon(A_GETCOND, &cond, sizeof(cond));
	if (rv_from_auditon == -1 && errno == ENOSYS) {
		T_SKIP("Kernel support for auditon(2) not available");
	}

	au_asid_t original_asid;
	au_id_t original_auid;
	get_asid_auid(&original_asid, &original_auid);

	// Change into newly created session
	new_session_flow(AU_ASSIGN_ASID, TERMIDM_UPDATE_SETAUDIT_ADDR, AU_IPv6, AUIDM_UPDATE_SETAUDIT_ADDR);

	// Assert we're in a new session
	au_asid_t new_asid;
	au_id_t new_auid;
	get_asid_auid(&new_asid, &new_auid);
	T_ASSERT_NE(new_asid, original_asid, NULL);
	T_ASSERT_NE(new_auid, original_auid, NULL);

	// Obtain session port for original session
	mach_port_t session_port;
	T_ASSERT_POSIX_SUCCESS(audit_session_port(original_asid, &session_port), "audit_session_port(2) succeeds");
	T_ASSERT_TRUE(MACH_PORT_VALID(session_port), NULL);

	// Join original session
	T_ASSERT_POSIX_SUCCESS(audit_session_join(session_port), "audit_session_join(2) succeeds");

	// Assert we're back in the original session
	get_asid_auid(&new_asid, &new_auid);
	T_ASSERT_EQ(new_asid, original_asid, NULL);
	T_ASSERT_EQ(new_auid, original_auid, NULL);
}
