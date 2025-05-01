#include <darwintest.h>
#include <darwintest_utils.h>

#define STATIC_IF_TEST
#define MARK_AS_FIXUP_TEXT

#include "../osfmk/kern/static_if_common.c"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true), T_META_TAG_VM_PREFERRED);

T_DECL(static_if_boot_arg, "Check the static if boot-arg parser")
{
	uint64_t v;

	v = static_if_boot_arg_uint64("key=2", "key", 0);
	T_EXPECT_EQ(v, 2ull, "parsing key correctly");

	v = static_if_boot_arg_uint64("key=2 key=1", "key", 0);
	T_EXPECT_EQ(v, 1ull, "parsing overrides");

	v = static_if_boot_arg_uint64("-key", "key", 0);
	T_EXPECT_EQ(v, 1ull, "parsing -key");

	v = static_if_boot_arg_uint64("key", "key", 0);
	T_EXPECT_EQ(v, 1ull, "parsing arg-less key");

	v = static_if_boot_arg_uint64("key=2 k", "key", 0);
	T_EXPECT_EQ(v, 2ull, "parsing ignoring prefixes at the end");

	v = static_if_boot_arg_uint64("key=0", "key", 1);
	T_EXPECT_EQ(v, 0ull, "parsing key=0 correctly");
	/* this should be rejected but PE_parse_boot_argn accepts it */
	v = static_if_boot_arg_uint64("key=0b", "key", 1);
	T_EXPECT_EQ(v, 0ull, "be bug to bug compatible with PE_parse_boot_argn");

	v = static_if_boot_arg_uint64("key=0x", "key", 1);
	T_EXPECT_EQ(v, 0ull, "be bug to bug compatible with PE_parse_boot_argn");

	v = static_if_boot_arg_uint64("key=0b1010", "key", 1);
	T_EXPECT_EQ(v, 10, "parsing binary correctly");

	v = static_if_boot_arg_uint64("key=-0b1010", "key", 1);
	T_EXPECT_EQ(v, -10, "parsing binary correctly");

	v = static_if_boot_arg_uint64("key=012", "key", 1);
	T_EXPECT_EQ(v, 10, "parsing fake octal correctly");

	v = static_if_boot_arg_uint64("key=-012", "key", 1);
	T_EXPECT_EQ(v, -10, "parsing hex correctly");

	v = static_if_boot_arg_uint64("key=0xa", "key", 1);
	T_EXPECT_EQ(v, 10, "parsing hex correctly");

	v = static_if_boot_arg_uint64("key=-0xa", "key", 1);
	T_EXPECT_EQ(v, -10, "parsing hex correctly");

	v = static_if_boot_arg_uint64("key=0xA", "key", 1);
	T_EXPECT_EQ(v, 10, "parsing hex correctly");

	v = static_if_boot_arg_uint64("key=-0xA", "key", 1);
	T_EXPECT_EQ(v, -10, "parsing hex correctly");

	/* invalid values */
	v = static_if_boot_arg_uint64("key=09", "key", 1);
	T_EXPECT_EQ(v, 1ull, "rejecting 09");

	v = static_if_boot_arg_uint64("key=8a9", "key", 1);
	T_EXPECT_EQ(v, 1ull, "rejecting 8a9");

	v = static_if_boot_arg_uint64("key=a", "key", 1);
	T_EXPECT_EQ(v, 1ull, "rejecting a");
}
