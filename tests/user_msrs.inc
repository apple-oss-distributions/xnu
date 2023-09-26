#define DECLARE_TEST_VARY_OP2(_op0, _op1, _n, _m)                  \
	DECLARE_TEST(_op0, _op1, _n, _m, 0)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 1)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 2)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 3)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 4)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 5)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 6)                            \
	DECLARE_TEST(_op0, _op1, _n, _m, 7)

#define DECLARE_TEST_VARY_M(_op0, _op1, _n)                        \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 0)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 1)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 2)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 3)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 4)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 5)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 6)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 7)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 8)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 9)                       \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 10)                      \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 11)                      \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 12)                      \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 13)                      \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 14)                      \
	DECLARE_TEST_VARY_OP2(_op0, _op1, _n, 15)

#define DECLARE_TEST_VARY_N(_op0, _op1)                            \
	DECLARE_TEST_VARY_M(_op0, _op1, 11)                            \
	DECLARE_TEST_VARY_M(_op0, _op1, 15)

#define DECLARE_TEST_VARY_OP1(_op0)                                \
	DECLARE_TEST_VARY_N(_op0, 0)                                   \
	DECLARE_TEST_VARY_N(_op0, 1)                                   \
	DECLARE_TEST_VARY_N(_op0, 2)                                   \
	DECLARE_TEST_VARY_N(_op0, 3)                                   \
	DECLARE_TEST_VARY_N(_op0, 4)                                   \
	DECLARE_TEST_VARY_N(_op0, 5)                                   \
	DECLARE_TEST_VARY_N(_op0, 6)                                   \
	DECLARE_TEST_VARY_N(_op0, 7)


DECLARE_TEST_VARY_OP1(3)

#undef DECLARE_TEST_VARY_OP1
#undef DECLARE_TEST_VARY_N
#undef DECLARE_TEST_VARY_M
#undef DECLARE_TEST_VARY_OP2

DECLARE_TEST(3, 3, 13, 0, 7) // SCXTNUM_EL0
