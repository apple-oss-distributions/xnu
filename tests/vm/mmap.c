#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <stdlib.h>
#include <fcntl.h>

extern __typeof__(mmap) __mmap;

#define N_INTS    (32 * 1024)
#define N_SIZE    (N_INTS * 4)

static int
make_temp_fd(void)
{
	char path[MAXPATHLEN] = "/tmp/mapfile.XXXXXX";
	const int batch = 128;
	int fd;

	T_ASSERT_POSIX_SUCCESS(fd = mkstemp(path), "mkstemp");
	T_ASSERT_POSIX_SUCCESS(unlink(path), "unlink");

	for (uint32_t i = 1; i <= N_INTS; i += batch) {
		uint32_t arr[batch];

		for (uint32_t j = 0; j < batch; j++) {
			arr[j] = i + j;
		}
		T_QUIET; T_ASSERT_EQ(write(fd, arr, sizeof(arr)), sizeof(arr), "write");
	}

	return fd;
}

#define K(n) ((n) << 10)

static struct mmap_spec {
	int             prot;
	int             flags;
	uint32_t        offs;
	uint32_t        size;
} specs[] = {
	{ PROT_READ, MAP_PRIVATE, K(0), N_SIZE - K(0)  },
	{ PROT_READ, MAP_PRIVATE, K(1), N_SIZE - K(1)  },
	{ PROT_READ, MAP_PRIVATE, K(4), N_SIZE - K(4)  },
	{ PROT_READ, MAP_PRIVATE, K(8), N_SIZE - K(8)  },
	{ PROT_READ, MAP_PRIVATE, K(16), N_SIZE - K(16) },
	{ PROT_READ, MAP_PRIVATE, K(32), N_SIZE - K(32) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(0), N_SIZE - K(0)  },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(1), N_SIZE - K(1)  },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(4), N_SIZE - K(4)  },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(8), N_SIZE - K(8)  },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(16), N_SIZE - K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(32), N_SIZE - K(32) },

	{ PROT_READ, MAP_PRIVATE, K(16) + K(0), K(16) },
	{ PROT_READ, MAP_PRIVATE, K(16) + K(1), K(16) },
	{ PROT_READ, MAP_PRIVATE, K(16) + K(4), K(16) },
	{ PROT_READ, MAP_PRIVATE, K(16) + K(8), K(16) },
	{ PROT_READ, MAP_PRIVATE, K(16) + K(16), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(16) + K(0), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(16) + K(1), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(16) + K(4), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(16) + K(8), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_UNIX03, K(16) + K(16), K(16) },

	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(0), N_SIZE - K(0)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(1), N_SIZE - K(1)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(4), N_SIZE - K(4)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(8), N_SIZE - K(8)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(16), N_SIZE - K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(32), N_SIZE - K(32) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(0), N_SIZE - K(0)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(1), N_SIZE - K(1)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(4), N_SIZE - K(4)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(8), N_SIZE - K(8)  },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(16), N_SIZE - K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(32), N_SIZE - K(32) },

	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(16) + K(0), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(16) + K(1), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(16) + K(4), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(16) + K(8), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED, K(16) + K(16), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(16) + K(0), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(16) + K(1), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(16) + K(4), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(16) + K(8), K(16) },
	{ PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_UNIX03, K(16) + K(16), K(16) },
	{ ~0 }
};

T_DECL(mmap_unaligned, "basic testing of mmap with various sizes and alignments")
{
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t         icount = VM_REGION_BASIC_INFO_COUNT_64;
	mach_vm_address_t              f_addr, r_addr;
	mach_vm_size_t                 f_size, r_size;
	uint32_t                       delta, size;
	uint32_t                      *p, *want_p;
	kern_return_t                  kr;
	int                            fd;

	fd = make_temp_fd();

	for (struct mmap_spec *it = specs; it->prot != ~0; it++) {
		T_LOG("mmap(NULL, prot=%#x, flags=%#x, fd=%d, offs=%d, size=%d)",
		    it->prot, it->flags, fd, it->offs, it->size);

		if (it->flags & MAP_FIXED) {
			f_size = PAGE_SIZE * 2 + it->size;
			kr = mach_vm_allocate(mach_task_self(), &f_addr, f_size,
			    VM_FLAGS_ANYWHERE);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate VA");
			want_p = (uint32_t *)(f_addr + PAGE_SIZE +
			    (it->offs & PAGE_MASK));
		} else {
			f_addr = 0;
			f_size = 0;
			want_p = NULL;
		}

		p = __mmap(want_p, it->size, it->prot, it->flags, fd, it->offs);

		if ((it->flags & MAP_UNIX03) && (it->offs & PAGE_MASK)) {
			errno_t rc = errno;
			T_QUIET; T_EXPECT_EQ((void *)p, MAP_FAILED, "mmap failure");
			T_QUIET; T_EXPECT_EQ(rc, EINVAL, "check errno");
			continue;
		} else if (want_p) {
			T_QUIET; T_EXPECT_EQ((void *)p, want_p, "mmap success");
		} else {
			T_QUIET; T_EXPECT_NE((void *)p, MAP_FAILED, "mmap success");
		}
		T_QUIET; T_EXPECT_EQ((uint32_t)p & PAGE_MASK, it->offs & PAGE_MASK,
		    "check offset");

		delta = it->offs & PAGE_MASK;
		size  = (delta + it->size + PAGE_MASK) & ~PAGE_MASK;
		r_addr = (vm_offset_t)p;
		kr = mach_vm_region(mach_task_self(), &r_addr, &r_size,
		    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &icount,
		    &(mach_port_t){0});
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "region");
		T_QUIET; T_EXPECT_EQ(r_addr, (mach_vm_address_t)p - delta,
		    "validate addr");
		T_QUIET; T_EXPECT_EQ(r_size, (mach_vm_size_t)size,
		    "validate size");

		for (uint32_t i = 0; i < it->size / 4; i += PAGE_SIZE / 4) {
			T_QUIET; T_EXPECT_EQ(p[i], it->offs / 4 + i + 1u,
			    "check value");
		}

		if (f_addr) {
			kr = mach_vm_deallocate(mach_task_self(), f_addr, f_size);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate VA");
		} else {
			/* mmap doesn't allow misaligned things ... */
			p    -= delta / 4;
			T_QUIET; T_EXPECT_POSIX_SUCCESS(munmap(p, size), 0,
			    "munmap(%p, %d)", p, size);
		}
	}
}
