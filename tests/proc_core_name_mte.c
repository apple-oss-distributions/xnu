#include <darwintest.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <TargetConditionals.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <arm_acle.h>

#define BUFFLEN  2048
#define TIMEOUT  10 /* Timeout in seconds to wait for coredumps to appear */

#define VM_FLAGS_MTE                    0x00002000

#define BUFFER_SZ_4MB (1024 * 1024 * 4)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("crash tools"));


// Mach-O parsing utilities :

struct mach_header_64 {
	uint32_t magic;          /* mach magic number identifier */
	uint32_t cputype;        /* cpu specifier */
	uint32_t cpusubtype;     /* machine specifier */
	uint32_t filetype;       /* type of file */
	uint32_t ncmds;          /* number of load commands */
	uint32_t sizeofcmds;     /* the size of all the load commands */
	uint32_t flags;          /* flags */
	uint32_t reserved;       /* reserved */
};

struct load_command {
	uint32_t cmd;                   /* type of load command */
	uint32_t cmdsize;               /* total size of command in bytes */
};

#define LC_SEGMENT_64       0x19        /* 64-bit segment of this file to be mapped */

struct segment_command_64 { /* for 64-bit architectures */
	uint32_t cmd;            /* LC_SEGMENT_64 */
	uint32_t cmdsize;        /* includes sizeof section_64 structs */
	char segname[16];    /* segment name */
	uint64_t vmaddr;         /* memory address of this segment */
	uint64_t vmsize;         /* memory size of this segment */
	uint64_t fileoff;        /* file offset of this segment */
	uint64_t filesize;       /* amount to map from the file */
	uint32_t maxprot;        /* maximum VM protection */
	uint32_t initprot;       /* initial VM protection */
	uint32_t nsects;         /* number of sections in segment */
	uint32_t flags;          /* flags */
};

typedef struct mach_header_64       mach_header_t;
typedef struct segment_command_64   segment_command_t;
#define LC_SEGMENT_CMD              LC_SEGMENT_64
typedef struct load_command         load_command_t;

#define FOREACH_SEGMENT_COMMAND(_header, _segment)                                                  \
for (const segment_command_t *seg_indx = NULL, \
	*_segment = (const segment_command_t *)((uintptr_t)(_header + 1));    \
	seg_indx < (const segment_command_t *)(NULL) + (_header)->ncmds;    \
	    ++seg_indx, _segment = (const segment_command_t *)((uintptr_t)_segment + _segment->cmdsize))

const segment_command_t * _Nullable
macho_get_next_segment(const mach_header_t * _Nonnull mh, const segment_command_t * _Nullable seg)
{
	FOREACH_SEGMENT_COMMAND(mh, nextseg) {
		if (nextseg->cmd != LC_SEGMENT_CMD) {
			continue;
		}
		if (seg == NULL) {
			return nextseg;
		}
		if (seg == nextseg) {
			seg = NULL;
		}
	}
	return NULL;
}

static const char corefile_ctl[] = "kern.corefile";
static const char coredump_ctl[] = "kern.coredump";
/* The directory where coredumps will be */
static const char dump_dir[] = "/cores";
/* The coredump location when we set kern.coredump ctl to something valid */
static const char valid_dump_fmt[] = "/cores/test-core.%d";
static const char ls_path[] = "/bin/ls";

/* A valid coredump location to test. */
static char valid_dump_loc[] = "/cores/test-core.%P";

static const struct rlimit lim_infty = {
	RLIM_INFINITY,
	RLIM_INFINITY
};

static volatile int stop_looking = 0;

static const struct timespec timeout = {
	TIMEOUT,
	0
};

static void
sigalrm_handler(int sig)
{
	(void)sig;
	stop_looking = 1;
	return;
}

static void
list_coredump_files()
{
	int ret;
	char buf[BUFFLEN] = { 0 };

	T_LOG("Contents of %s:", dump_dir);
	snprintf(buf, BUFFLEN, "%s %s", ls_path, dump_dir);
	ret = system(buf);
	T_ASSERT_POSIX_SUCCESS(ret, "Listing contents of cores directory");
	return;
}

static int
fork_and_wait_for_segfault()
{
	int pid, ret;
	int stat;
	pid = fork();
	if (pid == 0) {
		unsigned int *ptr = (unsigned int *)0x30; /* Cause a segfault so that we get a coredump */
		*ptr = 0xdeadd00d;
		exit(0);
	}
	T_ASSERT_TRUE(pid != -1, "Checking fork success in parent");

	ret = wait(&stat);
	T_ASSERT_TRUE(ret != -1, "Waited for child to segfault and dump core");
	T_ASSERT_FALSE(WIFEXITED(stat), "Seems that child process did not fail to execute");
	return pid;
}

static int
setup_coredump_kevent(struct kevent *kev, int dir)
{
	int ret;
	int kqfd;

	EV_SET(kev, dir, EVFILT_VNODE, EV_ADD, NOTE_WRITE, 0, NULL);
	kqfd = kqueue();
	T_ASSERT_POSIX_SUCCESS(kqfd, "kqueue: get kqueue for coredump monitoring");

	ret = kevent(kqfd, kev, 1, NULL, 0, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "kevent: setup directory monitoring for coredump");
	return kqfd;
}

static bool
check_coredump_contains_vm_addr(const char *path, vm_address_t vm_addr, size_t vm_size)
{
	int err;
	struct stat filestat;
	int fd = open(path, O_RDONLY);
	T_ASSERT_GE(fd, 0, "Failed to open file %s\n", path);
	err = fstat(fd, &filestat);
	T_ASSERT_POSIX_SUCCESS(err, "Failed to open the corefile to check vm region");

	T_WITH_ERRNO;
	const mach_header_t *macho = (const mach_header_t *) mmap(NULL, filestat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	T_ASSERT_NE(macho, MAP_FAILED, "Failed to mmap corefile\n");

	const segment_command_t * seg = NULL;

	while (vm_size > 0 && NULL != (seg = macho_get_next_segment(macho, seg))) {
		vm_address_t curr_end = seg->vmaddr + seg->vmsize;
		/* if vm_addr is included in the segment : */
		if ((vm_addr >= seg->vmaddr) && (vm_addr < curr_end)) {
			size_t seg_shift = vm_addr - seg->vmaddr;
			T_ASSERT_GE(
				(unsigned long long)seg->filesize,
				(unsigned long long)sizeof(unsigned long long) + seg_shift,
				"We expect corefile to contain an unsigned long long at least");
			unsigned long long *ptr = (unsigned long long*)((uintptr_t)seg->fileoff + (uintptr_t)macho + seg_shift);
			T_ASSERT_EQ(*ptr, (unsigned long long)0xbadc0ffee, "Corefile missing secret value");
			size_t curr_seg_tail = curr_end - vm_addr;
			size_t sub_size = MIN(curr_seg_tail, vm_size);
			vm_addr += sub_size;
			vm_size -= sub_size;
		}
	}
	return vm_size == 0;
}

static void
look_for_coredump_content(const char *format, int pid, int kqfd, struct kevent *kev, vm_address_t vm_addr, size_t vm_size)
{
	int ret = 0;
	int i = 0;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);
	snprintf(buf, BUFFLEN, format, pid);
	/*
	 * Something else might touch this directory. If we get notified and don't see
	 * anything, try a few more times before failing.
	 */
	alarm(TIMEOUT);
	while (!stop_looking) {
		/* Wait for kevent to tell us the coredump folder was modified */
		ret = kevent(kqfd, NULL, 0, kev, 1, &timeout);
		T_ASSERT_POSIX_SUCCESS(ret, "kevent: Waiting for coredump to appear");
		ret = -1;
		int fd = open(buf, O_RDONLY);
		if (fd > 0) {
			// found the file, stop looking
			ret = 0;
			close(fd);
			break;
		}

		T_LOG("Couldn't find coredump file (try #%d).", i + 1);
		i++;
	}
	alarm(0);

	if (ret == -1) {
		/* Couldn't find the coredump -- list contents of /cores */
		list_coredump_files();
	} else if (ret == 0) {
		bool vm_reg_contained = check_coredump_contains_vm_addr(buf, vm_addr, vm_size);
		T_ASSERT_EQ(vm_reg_contained, true, "Corefile %s doesn't have requested memory region", buf);
		ret = remove(buf);
	}

	T_ASSERT_POSIX_SUCCESS(ret, "Removing coredump file (should be at %s)", buf);
}

static void
sysctl_enable_coredumps(void)
{
	int ret;
	int enable_core_dump = 1;
	size_t oldlen = BUFFLEN;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);

	ret = sysctlbyname(coredump_ctl, buf, &oldlen, &enable_core_dump, sizeof(int));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: enable core dumps");

	ret = setrlimit(RLIMIT_CORE, &lim_infty);
	T_ASSERT_POSIX_SUCCESS(ret, "setrlimit: remove limit on maximum coredump size");
}

T_DECL(
	proc_core_name_mte,
	"Tests behavior of core dump when process has MTE hard mode enabled and MTE mapping with active tags",
	T_META_ASROOT(true),
	T_META_IGNORECRASHES("proc_core_name_mte.*"),
	T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
#if TARGET_OS_OSX
	T_META_ENABLED(true)
#else
	T_META_ENABLED(false)
#endif
	)
{
	DIR *dirp;
	int ret, pid, dir;
	char buf[BUFFLEN];
	memset(buf, 0, BUFFLEN);
	size_t oldlen = BUFFLEN;
	struct kevent kev;
	sig_t sig;
	int kqfd;

	sig = signal(SIGALRM, sigalrm_handler);
	T_WITH_ERRNO; T_EXPECT_NE(sig, SIG_ERR, "signal: set sigalrm handler");

	dirp = opendir(dump_dir);
	T_ASSERT_NOTNULL(dirp, "opendir: opening coredump directory");
	dir = dirfd(dirp);
	T_ASSERT_POSIX_SUCCESS(dir, "dirfd: getting file descriptor for coredump directory");
	kqfd = setup_coredump_kevent(&kev, dir);

	sysctl_enable_coredumps();
	vm_address_t vm_addr;
	kern_return_t kret = vm_allocate(mach_task_self(), &vm_addr, BUFFER_SZ_4MB,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);

	T_ASSERT_EQ(kret, 0, "vm_allocate failed to allocate MTE buffer");
	*(unsigned long long *)vm_addr = 0xbadc0ffee;

	uint8_t *tag_addr = __arm_mte_create_random_tag((void*)vm_addr, 0xffff);
	uint8_t *tag_addr_next = __arm_mte_increment_tag((void*)vm_addr + 16, 1);
	__arm_mte_set_tag(tag_addr);
	__arm_mte_set_tag(tag_addr_next);

	printf("New tagged addresses %p : %p\n", tag_addr, tag_addr_next);

	ret = sysctlbyname(corefile_ctl, buf, &oldlen, valid_dump_loc, strlen(valid_dump_loc));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: set valid core dump location, old value was %s", buf);
	memset(buf, 0, BUFFLEN);

	pid = fork_and_wait_for_segfault();
	look_for_coredump_content(valid_dump_fmt, pid, kqfd, &kev, vm_addr, BUFFER_SZ_4MB);

	vm_deallocate(mach_task_self(), vm_addr, BUFFER_SZ_4MB);
	closedir(dirp);
	close(kqfd);
	T_PASS("proc_core_name_mte PASSED");
}
