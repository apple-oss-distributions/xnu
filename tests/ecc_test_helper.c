/*
 * Copyright (c) 2021-2025 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <errno.h>
#include <mach/mach_vm.h>
#include <math.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

/*
 * ecc_test_helper is a convenience binary to induce various ECC errors
 * it's used by ECC-related tests: XNU unit tests and end-2-end coreos-tests
 */

/* Wait for a potential async ECC report, 1 second should be plenty. */
#define ECC_SLEEP (1)

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

static void
ecc_sysctl(const char *name, void *data, size_t size)
{
	int err = sysctlbyname(name, NULL, NULL, data, size);
	if (err) {
		printf("Failed to call sysctl %s: (%d) %s\n", name, errno, strerror(errno));
		exit(errno);
	}
}

typedef enum command {
	Yfoo,
	Xfoo,
	Yatan,
	Xatan,
	Xclean,
	Xdirty,
	Xcopyout,
	Xmmap_clean,
	Xmmap_dirty,
	Xclean_write,
	Xdirty_write,

	Xwired,
	Xkernel,
	Xmte_active,

	rmdb,

	BAD_COMMAND
} command;

typedef struct{
	char *key;
	enum command val;
	const char *description;
} command_t;

#define define_command(name, description) {#name, name, description}

static command_t commands[] = {
	define_command(Yfoo, "invoke a local TEXT function."),
	define_command(Xfoo, "inject ECC and invoke a local TEXT function."),
	define_command(Yatan, "invoke a shared library TEXT function."),
	define_command(Xatan, "inject ECC and invoke a shared library TEXT function."),
	define_command(Xclean, "read from a clean DATA page."),
	define_command(Xdirty, "read from a dirty DATA page."),
	define_command(Xmmap_clean, "read from a clean mmap'd page"),
	define_command(Xmmap_dirty, "read from a dirty mmap'd page"),
	define_command(Xcopyout, "inject an ECC error and then trigger it via a copyout"),
	define_command(Xclean_write, "write to a clean DATA page."),
	define_command(Xdirty_write, "write to a dirty DATA page."),
	define_command(Xwired, "inject an ECC on wired page"),
	define_command(Xkernel, "inject an ECC on kernel page"),
	define_command(Xmte_active, "inject an ECC on MTE active tag storage page"),
	define_command(rmdb, "<path> - removes the file at <path>, entitled to delete ECC dbs"),
};

command
get_command(char *key)
{
	int i;
	for (i = 0; i < sizeof(commands) / sizeof(command_t); i++) {
		command_t elem = commands[i];
		if (strcmp(elem.key, key) == 0) {
			return elem.val;
		}
	}
	return BAD_COMMAND;
}

void
print_commands(void)
{
	printf("Valid commands:\n");
	for (int i = 0; i < sizeof(commands) / sizeof(command_t); i++) {
		command_t elem = commands[i];
		printf("\t%s - %s \n", elem.key, elem.description);
	}
}

void
usage(void)
{
	printf("usage: [-v] <command> [<args>]\n");
	printf("\n");
	print_commands();
}

int
main(int argc, char **argv)
{
	void *addr;
	int *page;
	size_t s = sizeof(addr);
	static volatile int readval;
	static volatile double readval_d;
	int cmd = 1;

	/*
	 * check for -v for verbose output
	 */
	if (argc > 1 && strcmp(argv[1], "-v") == 0) {
		verbose = 1;
		cmd = 2;
	}

	/*
	 * needs to run as root for sysctl
	 */
	if (geteuid() != 0) {
		printf("Helper not running as root, exiting\n");
		exit(-1);
	}

	if (cmd >= argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	switch (get_command(argv[cmd])) {
	case Yfoo:
		foo();
		break;
	case Xfoo:
		PRINTF("Warm up call to foo()\n");
		foo();

		addr = (void *)ptrauth_strip(&foo, ptrauth_key_function_pointer);
		ecc_sysctl("vm.ecc.inject_error_va", &addr, s);

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
		ecc_sysctl("vm.ecc.inject_error_va", &addr, s);

		readval_d = atan(zero);
		PRINTF("After injection, atan(0) is %g\n", readval_d);
		break;
	case Xclean:
		readval = x.big_data[35];
		PRINTF("initial read of clean x.big_data[35] is %d\n", readval);

		addr = (void *)&x.big_data[35];
		ecc_sysctl("vm.ecc.inject_error_va", &addr, s);

		readval = x.big_data[35];
		PRINTF("After injection, read of x.big_data[35] is %d\n", readval);
		break;
	case Xdirty:
		x.big_data[36] = (int)random();
		PRINTF("initial read of dirty x.big_data[36] is %d\n", x.big_data[36]);

		addr = (void *)&x.big_data[36];
		ecc_sysctl("vm.ecc.inject_error_va", &addr, s);

		readval = x.big_data[36];
		PRINTF("After injection, read of x.big_data[36] is %d\n", readval);
		break;
	case Xmmap_clean:
		page = (int *)mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
		page = (int *)((char *)page + PAGE_SIZE);

		readval = *page;
		PRINTF("initial read of clean page %p is %d\n", page, readval);

		ecc_sysctl("vm.ecc.inject_error_va", &page, s);

		readval = *page;
		PRINTF("second read of page is %d\n", readval);
		break;
	case Xmmap_dirty:
		page = (int *) mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
		page = (int *)((char *)page + PAGE_SIZE);

		*page = 0xFFFF;
		PRINTF("initial read of dirty page %p is %d (after write)\n", page, *page);

		ecc_sysctl("vm.ecc.inject_error_va", &page, s);

		readval = *page;
		PRINTF("second read of page is %d\n", readval);
		break;
	case Xcopyout: {
		x.big_data[37] = (int)random();
		PRINTF("initial read of dirty x.big_data[37] is %d\n", x.big_data[37]);

		addr = (void *)&x.big_data[37];
		ecc_sysctl("vm.ecc.inject_error_copyout", &addr, s);

		readval = x.big_data[37];
		PRINTF("After injection, read of dirty x.big_data[37] is %d\n", readval);
		break;
	}
	case Xclean_write: {
		volatile int *addr = &x.big_data[38];

		ecc_sysctl("vm.ecc.inject_error_va", &addr, s);

		/*
		 * We expect this access to trigger a sync abort, since the
		 * underlying page is not dirty we can just reload the page
		 * transparently to the process.
		 */
		*addr = 0xecc;

		printf("After injection and a write, we read %d\n", *addr);
		break;
	}
	case Xdirty_write: {
		volatile int *addr = &x.big_data[39];

		*addr = 0xecc;
		printf("initial read of dirty memory is %d\n", *addr);

		ecc_sysctl("vm.ecc.inject_error_va", &addr, s);

		*addr = 0xeccecc;

		sleep(ECC_SLEEP);
		PRINTF("Slept for %d second(s)\n", ECC_SLEEP);

		/*
		 * After wrtiting to poisoned memory we expect a SError which
		 * will disconnect the page. If we read that memory again we
		 * will get a SIGBUS.
		 */
		printf("After injection, we read %d\n", *addr);

		break;
	}
	case Xwired: {
		page = (int *) mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
		page = (int *)((char *)page + PAGE_SIZE);
		PRINTF("page addr %p\n", page);
		if (mlock(page, PAGE_SIZE)) {
			printf("Failed to wire, errno: %d", errno);
			exit(EXIT_SUCCESS);
		}

		ecc_sysctl("vm.ecc.inject_error_va", &page, s);

		readval = *page;
		PRINTF("wire trigger value: %d\n", readval);

		sleep(ECC_SLEEP);

		PRINTF("Slept for %u second(s), did not get an ECC.\n", ECC_SLEEP);

		break;
	}
	case Xkernel: {
		PRINTF("Inducing ECC on kernel page\n");

		ecc_sysctl("vm.ecc.inject_error_kernel", NULL, 0);

		break;
	}
	case Xmte_active: {
		PRINTF("Inducing ECC on MTE active storage page\n");

		ecc_sysctl("vm.ecc.inject_error_mte_active", NULL, 0);

		break;
	}
	case rmdb:
		if (cmd + 1 >= argc) {
			printf("usage: rmdb <path>\n");
			exit(EXIT_FAILURE);
		}

		const char *path = argv[cmd + 1];
		int rc;

		/**
		 * The iSCPreboot filesystem apparently does not know how to report different
		 * errors, all I ever got both from access() and remove() was -1 or 0.
		 * Not entitled -- -1. No file -- -1.
		 * Keep that in mind if you are trying to debug.
		 */
		rc = remove(path);
		if (rc == 0) {
			printf("removed: %s\n", path);
		} else {
			printf("couldn't remove: %s, reason: %d\n", path, rc);
			exit(EXIT_FAILURE);
		}
		break;

	case BAD_COMMAND:
		printf("Unknown command\n\n");
		print_commands();
		exit(EXIT_FAILURE);

		break;
	}

	exit(EXIT_SUCCESS);
}
