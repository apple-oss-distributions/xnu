#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <assert.h>
#include <sysexits.h>
#include <getopt.h>
#include <spawn.h>
#include <stdbool.h>
#include <sys/sysctl.h>
#include <mach/mach_time.h>
#include <mach/mach.h>
#include <mach/semaphore.h>
#include <TargetConditionals.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdatomic.h>

