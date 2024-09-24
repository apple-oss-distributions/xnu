#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ptrauth.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <mach/mach_vm.h>

/*
 * ecc_test_helper is a convenience binary to induce various ECC errors
 * it's used by ECC-related tests: XNU unit tests and end-2-end coreos-tests
 */


int verbose = 0;
#define PRINTF(...) \
	if (verbose) { \
	        printf(__VA_ARGS__); \
	}

__attribute__((noinline))
static void
foo(void)
{
	PRINTF("In foo()\n");
	fflush(stdout);
}

volatile struct data {
	char buffer1[16 * 1024];
	int big_data[16 * 1024];
	char buffer2[16 * 1024];
} x = {
	.big_data = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	}
};

/*
 * volatile to stop the compiler from optimizing away calls to atan()
 */
volatile double zero = 0.0;


typedef enum TestCase {
	Yfoo,
	Xfoo,
	Yatan,
	Xatan,
	Xclean,
	Xdirty,
	Xcopyout,
	Xmmap_clean,
	Xmmap_dirty,
	Xwired,
	kernel,

	BAD_TEST_CASE
} TestCase;

typedef struct{
	char *key;
	enum TestCase val;
} testcase_t;

#define testCase(name) {#name, name}

static testcase_t testcases[] = {
	testCase(Yfoo),
	testCase(Xfoo),
	testCase(Yatan),
	testCase(Xatan),
	testCase(Xclean),
	testCase(Xdirty),
	testCase(Xmmap_clean),
	testCase(Xmmap_dirty),
	testCase(Xcopyout),
	testCase(kernel),
	testCase(Xwired)
};

TestCase
get_testcase(char *key)
{
	int i;
	for (i = 0; i < sizeof(testcases) / sizeof(testcase_t); i++) {
		testcase_t elem = testcases[i];
		if (strcmp(elem.key, key) == 0) {
			return elem.val;
		}
	}
	return BAD_TEST_CASE;
}

int
main(int argc, char **argv)
{
	void *addr;
	int *page;
	size_t s = sizeof(addr);
	int err;
	static volatile int readval;
	static volatile double readval_d;

	/*
	 * check for -v for verbose output
	 */
	if (argc > 1 && strcmp(argv[1], "-v") == 0) {
		verbose = 1;
	}

	/*
	 * needs to run as root for sysctl
	 */
	if (geteuid() != 0) {
		printf("Test not running as root, exiting\n");
		exit(-1);
	}

	/*
	 * The argument determines what test to try.
	 * "Y{name}" is a test, "X{name}" does the test after injecting an ECC error
	 *
	 * Tests:
	 * "foo" - invoke a local TEXT function.
	 * "atan" - invoke a shared library TEXT function.
	 * "clean" - read from a clean DATA page
	 * "dirty" - read from a dirty DATA page
	 * "mmap_clean" - read from a clean mmap'd page
	 * "mmap_dirty" - read from a dirty mmap'd page
	 */
	switch (get_testcase(argv[argc - 1])) {
	case Yfoo:
		foo();
		break;
	case Xfoo:
		PRINTF("Warm up call to foo()\n");
		foo();

		addr = (void *)ptrauth_strip(&foo, ptrauth_key_function_pointer);
		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &addr, s);

		PRINTF("Calling foo() after injection\n");
		foo();

		break;
	case Yatan:
		readval_d = atan(zero);
		PRINTF("atan(0) is %g\n", readval_d);
		break;
	case Xatan:
		readval_d = atan(zero);
		PRINTF("Warmup call to atan(0) is %g\n", readval_d);

		addr = (void *)ptrauth_strip(&atan, ptrauth_key_function_pointer);
		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &addr, s);

		readval_d = atan(zero);
		PRINTF("After injection, atan(0) is %g\n", readval_d);
		break;
	case Xclean:
		readval = x.big_data[35];
		PRINTF("initial read of clean x.big_data[35] is %d\n", readval);

		addr = (void *)&x.big_data[35];
		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &addr, s);

		readval = x.big_data[35];
		PRINTF("After injection, read of x.big_data[35] is %d\n", readval);
		break;
	case Xdirty:
		x.big_data[36] = (int)random();
		PRINTF("initial read of dirty x.big_data[36] is %d\n", x.big_data[36]);

		addr = (void *)&x.big_data[36];
		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &addr, s);

		readval = x.big_data[36];
		PRINTF("After injection, read of x.big_data[36] is %d\n", readval);
		break;
	case Xmmap_clean:
		page = (int *)mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
		page = (int *)((char *)page + PAGE_SIZE);

		readval = *page;
		PRINTF("initial read of clean page %p is %d\n", page, readval);

		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &page, s);

		readval = *page;
		PRINTF("second read of page is %d\n", readval);
		break;
	case Xmmap_dirty:
		page = (int *) mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
		page = (int *)((char *)page + PAGE_SIZE);

		*page = 0xFFFF;
		PRINTF("initial read of dirty page %p is %d (after write)\n", page, *page);

		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &page, s);

		readval = *page;
		PRINTF("second read of page is %d\n", readval);
		break;
	case Xcopyout:
		x.big_data[37] = (int)random();
		PRINTF("initial read of dirty x.big_data[37] is %d\n", x.big_data[37]);

		addr = (void *)&x.big_data[37];
		err = sysctlbyname("vm.inject_ecc_copyout", NULL, NULL, &addr, s);
		if (err) {
			PRINTF("copyout return %d\n", err);
			exit(err);
		}

		readval = x.big_data[37];
		PRINTF("After injection, read of dirty x.big_data[37] is %d\n", readval);
		break;
	case Xwired:
		page = (int *) mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
		page = (int *)((char *)page + PAGE_SIZE);
		PRINTF("page addr %p\n", page);
		if (mlock(page, PAGE_SIZE)) {
			printf("Failed to wire, errno: %d", errno);
			exit(0);
		}

		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &page, s);

		readval = *page;
		PRINTF("wire trigger value: %d", readval);

		break;
	case kernel:
		PRINTF("Inducing ECC on kernel page\n");

		addr = (void *)1;         /* used to flag some kernel page */
		err = sysctlbyname("vm.inject_ecc", NULL, NULL, &addr, s);
		exit(0);

		break;
	case BAD_TEST_CASE:
		printf("Unknown test case\n\n");
		printf("Valid tests:\n");
		for (int i = 0; i < sizeof(testcases) / sizeof(testcase_t); i++) {
			testcase_t elem = testcases[i];
			printf("%d. %s\n", i + 1, elem.key);
		}
		printf("\nY{name} is a test, X{name} does the test after injecting an ECC error\n");

		exit(1);

		break;
	}

	exit(0);
}
