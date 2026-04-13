#include <chrono>
#include <cstdio>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fstream>
#include <iostream>
#include <random>
#include <shared_mutex>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <csignal>
#include <stdexcept>
#include <memory>
#include <getopt.h>
#include <stdint.h>
#include <inttypes.h>

#include <future>
#include <thread>
#include <map>
#include <vector>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_OWNER("tgal2"),
	T_META_BOOTARGS_SET("enable_skstb=1"),
	T_META_ASROOT(true));

/** The following are modes that determine the way in which the created objects will be re-mapped to the task's memory.
 *  The test behaves as follows according to the chosen policy:
 *  RandomPartition - creates a buffer for each (randomly sized) part of each object. Every page of every object will be re-mapped exactly once.
 *  OneToMany - creates multiple mappings of the entire object.
 *  Overwrite - same as OneToMany, only that a portion of each mapping's pages will be overwritten, creating double the amount of mappings in total.
 *  Topology - creates mappings according to different topologies.
 */
enum class MappingPolicy {
	RandomPartition,
	OneToMany,
	Overwrite,
	Topology,
};

struct InterrupterParams {
	unsigned int minimum_busy_time_us;
	unsigned int maximum_busy_time_us;
	double       interrupter_probability;  // Inverse of the expected wait time (us) of the interrupter
};

static const InterrupterParams default_interrupter_params = {
	.minimum_busy_time_us    = 50,
	.maximum_busy_time_us    = 100,
	.interrupter_probability = 0.01, // Interrupt approximately every 100us
};

struct TestParams {
	uint32_t num_objects;
	uint64_t obj_size;
	uint32_t runtime_secs;
	uint32_t num_threads;
	MappingPolicy policy;
	uint32_t mpng_flags;
	bool is_cow;
	bool is_file;
	bool slow_paging;
	bool enable_interrupters;
	InterrupterParams interrupter_params;
};

struct MappingArgs {
	task_t arg_target_task = mach_task_self();
	mach_vm_address_t arg_target_address = 0;
	uint64_t arg_mapping_size = 0;
	uint32_t arg_mask = 0;
	uint32_t arg_flags = 0;
	task_t arg_src_task = mach_task_self();
	mach_vm_address_t arg_src_address = 0;
	bool arg_copy = false;
	uint32_t arg_cur_protection = 0;
	uint32_t arg_max_protection = 0;
	uint32_t arg_inheritance = VM_INHERIT_SHARE;
};

struct status_counters {
	uint32_t success;
	uint32_t fail;
} status_counters;

#if WITH_REALTIME_THREADS
uint64_t
nanos_to_abs(uint64_t nanos)
{
	static mach_timebase_info_data_t timebase_info = {};

	if (timebase_info.numer == 0 || timebase_info.denom == 0) {
		kern_return_t kr = mach_timebase_info(&timebase_info);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_timebase_info");
	}

	return nanos * timebase_info.denom / timebase_info.numer;
}
#endif

static std::random_device rd;
static std::mt19937 gen(rd());

static uint64_t
random_between(
	uint64_t a, uint64_t b)
{
	std::uniform_int_distribution<> dis(a, b);
	return dis(gen);
}

static bool
is_cpu_pinning_supported()
{
	int32_t cpu = -1;
	size_t cpu_size = sizeof(cpu);
	int ret = sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &cpu, sizeof(cpu));
	return ret == 0;
}

static void
pin_thread_to_cpu(int32_t cpu)
{
	int ret = sysctlbyname("kern.sched_thread_bind_cpu", NULL, NULL, &cpu, sizeof(cpu));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(kern.sched_thread_bind_cpu)");
}

static void
make_highpriority(InterrupterParams const &params)
{
	struct sched_param param = {
		.sched_priority = sched_get_priority_max(SCHED_RR)
	};
	int ret = pthread_setschedparam(pthread_self(), SCHED_RR, &param);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Failed to make thread high priority");
}

class TestRuntime
{
public:
	// Member functions:
	int
	wait_for_status(
		int runtime_secs)
	{
		std::unique_lock<std::mutex> lock(mutex);
		auto now = std::chrono::system_clock::now();
		auto deadline = now + std::chrono::seconds(runtime_secs);
		state = running;
		while (state == running) {
			if (cond.wait_until(lock, deadline) == std::cv_status::timeout) {
				state = complete;
			}
		}
		if (state == complete) {
			return 0;
		} else {
			return 1;
		}
	}

	enum state {
		paused,
		running,
		error,
		complete
	};

	// Data members:
	std::atomic<state> state{paused};
	std::mutex mutex;

private:
	std::condition_variable cond;
};

TestRuntime runner;

/**
 * Responsible for creating the actual mapping into vm, performing actions on a
 * mapping or a page, manage the threads which perform operations on this
 * mapping.
 */
class Mapping
{
	using vm_op = std::function<bool (Mapping *)>;

public:
	// Constructor:
	Mapping(uint32_t _id, uint64_t _offset_in_pages, MappingArgs _args, uint32_t _fd)
		: id(_id), offset_in_pages(_offset_in_pages), args(_args), fd(_fd), lock(std::make_shared<std::shared_mutex>()), src_mapping(std::nullopt), is_mapped(false)
	{
		num_pages = args.arg_mapping_size / PAGE_SIZE;
		op_denom = num_pages;
		create_mapping();
	}

	// Comparator for sorting by id
	static bool
	compare_by_id(
		const Mapping &a, const Mapping &b)
	{
		return a.id < b.id;
	}

	// Member functions:

	// Creation:

	kern_return_t
	remap_fixed()
	{
		kern_return_t kr = mach_vm_remap(args.arg_target_task, &args.arg_target_address, args.arg_mapping_size,
		    args.arg_mask, VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, args.arg_src_task,
		    args.arg_src_address + offset_in_pages * PAGE_SIZE, args.arg_copy, (vm_prot_t *)&(args.arg_cur_protection),
		    (vm_prot_t *)&(args.arg_max_protection), args.arg_inheritance);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		is_mapped = true;
		return kr;
	}

	int
	create_mapping()
	{
		kern_return_t kr = remap_fixed();
		if (kr != KERN_SUCCESS) {
			throw std::runtime_error("mach_vm_remap failed: " + std::string(mach_error_string(kr)) + "\n");
		}
		return 0;
	}

	void
	set_src_mapping(
		Mapping &other)
	{
		src_mapping = other;
	}

	// Operations to be done by the ran threads:

	kern_return_t
	deallocate_no_lock()
	{
		is_mapped = false;
		kern_return_t kr = mach_vm_deallocate(args.arg_src_task, args.arg_target_address, args.arg_mapping_size);
		return kr;
	}

	bool
	realloc_no_parent()
	{
		std::unique_lock<std::shared_mutex> my_unique(*lock);

		kern_return_t kr = remap_fixed();
		if (kr != KERN_SUCCESS) {
			return false;
		}
		return true;
	}

	bool
	realloc_with_parent()
	{
		std::unique_lock<std::shared_mutex> my_unique(*lock, std::defer_lock);
		std::unique_lock<std::shared_mutex> parent_unique(*(src_mapping->get().lock), std::defer_lock);
		std::scoped_lock l{my_unique, parent_unique};

		kern_return_t kr = remap_fixed();
		if (kr != KERN_SUCCESS) {
			return false;
		}
		return true;
	}

	bool
	op_dealloc()
	{
		std::unique_lock<std::shared_mutex> my_unique(*lock);

		kern_return_t kr = deallocate_no_lock();
		if (kr != KERN_SUCCESS) {
			return false;
		}
		return true;
	}

	bool
	op_realloc()
	{
		// std::this_thread::sleep_for(std::chrono::microseconds(50));
		if (src_mapping) {
			return realloc_with_parent();
		} else {
			return realloc_no_parent();
		}
	}

	bool
	op_protect()
	{
		kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)args.arg_target_address,
		    (num_pages / op_denom) * PAGE_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE);
		if (kr != KERN_SUCCESS) {
			return false;
		}
		return true;
	}

	bool
	op_wire()
	{
		std::this_thread::sleep_for(std::chrono::microseconds(50));
		uint32_t err = mlock((void *)args.arg_target_address, (num_pages / op_denom) * PAGE_SIZE);
		if (err) {
			return false;
		}
		return true;
	}

	bool
	op_write()
	{
		std::shared_lock<std::shared_mutex> my_shared(*lock);
		if (!is_mapped) {
			return false;
		}
		// Modify only the last byte of each page.
		for (uint64_t i = 1; i <= num_pages / op_denom; i++) {
			((char *)args.arg_target_address)[i * PAGE_SIZE - 1] = 'M'; // M marks it was written via the mapping (for debugging purposes)
		}

		// No need to sync to the file. It will be written when paged-out (which happens all the time).

		return true;
	}


	bool
	op_unwire()
	{
		uint32_t err = munlock((void *)args.arg_target_address, (num_pages / op_denom) * PAGE_SIZE);
		if (err) {
			return false;
		}
		return true;
	}

	bool
	op_write_direct()
	{
		std::this_thread::sleep_for(std::chrono::microseconds(50));

		if (!fd) {
			return false; // Return early if no file descriptor (no file-backed mapping)
		}

		std::shared_lock<std::shared_mutex> my_shared(*lock);
		if (!is_mapped) {
			return false;
		}

		// Modify only the last byte of each page.
		for (uint64_t i = 1; i <= num_pages / op_denom; i++) {
			((char *)args.arg_target_address)[i * PAGE_SIZE - 1] = 'D'; // D marks it was written using op_write_Direct (for debugging purposes)
		}

		if (fcntl(fd, F_NOCACHE, true)) {
			auto err = errno;
			throw std::runtime_error("fcntl failed. err=" + std::to_string(err) + "\n");
		}
		if (lseek(fd, 0, SEEK_SET) == -1) {
			throw std::runtime_error("lseek failed to move cursor to beginning. err=" + std::to_string(errno));
		}

		int num_bytes = write(fd, (void *)(args.arg_target_address), (num_pages / op_denom) * PAGE_SIZE);

		if (num_bytes == -1) {
			printf("num_bytes=%d", num_bytes);
			return false;
		}

		return true;
	}

	bool
	op_pageout()
	{
		if (madvise((void *)args.arg_target_address, (num_pages / op_denom) * PAGE_SIZE, MADV_PAGEOUT)) {
			return false;
		}
		return true;
	}

	bool
	run_op(const std::pair<vm_op, std::string> *op)
	{
		bool ret = false;
		ret = op->first(this);

		/* Never let the denominator be zero. */
		uint32_t new_denom = (op_denom * 2) % num_pages;
		op_denom = new_denom > 0 ? new_denom : 1;

		return ret;
	}

	// Miscellaneous:

	void
	create_gap_before()
	{
		mach_vm_address_t to_dealloc = args.arg_target_address - PAGE_SIZE;
		kern_return_t kr = mach_vm_deallocate(mach_task_self(), to_dealloc, PAGE_SIZE);
		if (kr != KERN_SUCCESS) {
			throw std::runtime_error("mach_vm_deallocate failed: " + std::string(mach_error_string(kr)) + "\n");
		}
	}

	void
	adjust_addresses_and_offset(
		uint64_t detached_num_pages, uint64_t detached_size)
	{
		args.arg_src_address += detached_size;
		args.arg_target_address += detached_size;
		offset_in_pages += detached_num_pages;
	}

	void
	shrink_size(
		uint64_t detached_num_pages, uint64_t detached_size)
	{
		num_pages -= detached_num_pages;
		args.arg_mapping_size -= detached_size;
	}

	/* Fix the wrapper of the mapping after overwriting a part of it, to keep it aligned to real vmmap_entry */
	void
	fix_overwritten_mapping(
		uint64_t detached_num_pages)
	{
		uint64_t detached_size = detached_num_pages * PAGE_SIZE;
		id *= 2;
		shrink_size(detached_num_pages, detached_size);
		adjust_addresses_and_offset(detached_num_pages, detached_size);
		create_gap_before();
	}

	void
	print_mapping()
	{
		T_LOG("\tMAPPING #%2d, from address: %llx, to address: %llx, offset: %2llu, size: %4llu "
		    "pages\n",
		    id, args.arg_src_address, args.arg_target_address, offset_in_pages, num_pages);
	}

	uint64_t
	get_end()
	{
		return offset_in_pages + args.arg_mapping_size / PAGE_SIZE - 1;
	}

	void
	add_child(Mapping *other)
	{
		children.emplace_back(other);
	}

	void
	print_as_tree(const std::string &prefix = "", bool isLast = true)
	{
		T_LOG("%s%s%d", prefix.c_str(), (isLast ? "└── " : "├── "), id);

		std::string newPrefix = prefix + (isLast ? "    " : "│   ");

		for (uint32_t i = 0; i < children.size(); i++) {
			children[i]->print_as_tree(newPrefix, i == children.size() - 1);
		}
	}

	// Data members:

	uint32_t id = 0;
	uint64_t offset_in_pages = 0;
	MappingArgs args;
	uint64_t num_pages = 0;
	std::vector<Mapping *> children;
	uint32_t fd = 0;
	std::shared_ptr<std::shared_mutex> lock;
	std::optional<std::reference_wrapper<Mapping> > src_mapping;
	bool is_mapped; // set on remap() and cleared on deallocate().

	/**
	 * Regarding the locks: (reasoning for shared_ptr)
	 * In some cases (MAppingsManager::policy==MappingPolicy::Topology), the source for this mapping is another mapping.
	 * This case requires, in certain ops (op_de_re_allocate()), to also hold the source's lock.
	 * That means lock is going to be under shared ownership and therefore the locks should be in a shared_ptr.
	 */
	uint32_t op_denom = 1; // tells the various operations what part of num_pages to include.
	static inline std::vector<std::pair<vm_op, const std::string> > ops = {
		{&Mapping::op_protect, "protect"},
		{&Mapping::op_wire, "wire"},
		{&Mapping::op_write, "write"},
		{&Mapping::op_unwire, "unwire"},
		{&Mapping::op_pageout, "pageout"}};
	/*
	 * The following is disabled due to a deadlock it causes in the kernel too frequently
	 * (and we want a running stress test). See rdar://146761078
	 * Once this deadlock is solved, we should uncomment it.
	 */
	// {&Mapping::op_write_direct, "write_direct"},
};

/**
 * Creates and wraps the memory object
 */
class Object
{
public:
	// Default constructor:
	Object() : id(0), num_pages(0)
	{
	}

	// Constructor:
	Object(
		uint32_t _id, uint32_t num_pages)
		: id(_id), num_pages(num_pages)
	{
	}

	// Memeber functions:

	// Creation:

	int
	open_file_slow_paging()
	{
		std::string slow_file = std::string(slow_dmg_path) + "/file.txt";
		fd = open(slow_file.c_str(), O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
		if (fd < 0) {
			throw std::runtime_error("open() failed. err=" + std::to_string(errno) + "\n");
		}

		T_LOG("File created in slow ramdisk: %s\n", slow_file.c_str());

		return fd;
	}

	int
	open_file()
	{
		std::string template_str = "/tmp/some_file_" + std::to_string(id) + "XXXXXX";
		auto template_filename = std::make_unique<char[]>(template_str.length());
		strcpy(template_filename.get(), template_str.c_str());

		fd = mkstemp(template_filename.get());
		if (fd == -1) {
			throw std::runtime_error("mkstemp failed. err=" + std::to_string(errno) + "\n");
		}

		T_LOG("Temporary file created: %s\n", template_filename.get());

		return fd;
	}

	void
	close_file()
	{
		close(fd);
		fd = 0;
	}

	int
	create_source_from_file(bool slow_paging)
	{
		// File opening/creation:
		int fd = 0;
		struct stat st;

		if (slow_paging) {
			fd = open_file_slow_paging();
		} else {
			fd = open_file();
		}

		if (fd < 0) {
			return fd;
		}

		if (ftruncate(fd, num_pages * PAGE_SIZE) < 0) {
			throw std::runtime_error("ftruncate failed. err=" + std::to_string(errno) + "\n");
		}

		// Mapping file to memory:
		src = (mach_vm_address_t)mmap(NULL, num_pages * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if ((void *)src == MAP_FAILED) {
			throw std::runtime_error("mmap failed. err=" + std::to_string(errno) + "\n");
		}

		return 0;
	}

	int
	create_source_anon()
	{
		uint32_t anywhere_flag = TRUE;
		kern_return_t kr = mach_vm_allocate(mach_task_self(), &src, num_pages * PAGE_SIZE, anywhere_flag);
		if (kr != KERN_SUCCESS) {
			throw std::runtime_error("mach_vm_allocate failed: " + std::string(mach_error_string(kr)) + "\n");
		}
		return 0;
	}

	int
	create_source(
		bool is_file, bool slow_paging)
	{
		if (is_file) {
			return create_source_from_file(slow_paging);
		} else {
			return create_source_anon();
		}
	}

	static uint64_t
	random_object_size(
		uint64_t obj_size)
	{
		uint32_t min_obj_size = 16; // (in pages)
		return random_between(min_obj_size, obj_size);
	}

	// Miscellaneous:

	void
	print_object()
	{
		T_LOG(" -----------------------------------------------------------------------------");
		T_LOG(" OBJECT #%d, size: %llu pages, object address: %llx\n", id, num_pages, src);
	}

	// Data members:
	uint32_t id = 0;
	uint64_t num_pages = 0;
	mach_vm_address_t src = 0;
	int fd = 0;
	static inline char slow_dmg_path[] = "/Volumes/apfs-slow";
};

/**
 * Creates and manages the different mappings of an object.
 */
class MappingsManager
{
public:
	// Constructor:
	MappingsManager(
		const Object &_obj, MappingPolicy _policy)
		: obj(_obj), policy(_policy)
	{
	}

	// Destructor:
	~MappingsManager()
	{
		for (uint32_t i = 0; i < ranges.size(); i++) {
			if (buffers[i]) {
				mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)buffers[i], ranges[i].second - ranges[i].first + 2);
				buffers[i] = nullptr;
			}
		}
	}

	enum topology {
		chain,
		star,
		ternary,
		random
	};

	// Member functions:

	std::string
	topo_to_string()
	{
		switch (topo) {
		case chain:
			return "chain";
		case star:
			return "star";
		case ternary:
			return "ternary";
		case random:
			return "random";
		default:
			return "unknown";
		}
	}

	// Partition stuff:

	void
	create_general_borders(
		std::vector<uint64_t> &general_borders)
	{
		uint64_t gap = obj.num_pages / (num_mappings);
		general_borders.emplace_back(1);
		for (uint32_t i = 1; i < (num_mappings); i++) {
			general_borders.emplace_back(gap * i);
		}
	}

	void
	create_borders(
		std::vector<uint64_t> &borders)
	{
		std::vector<uint64_t> general_borders;
		create_general_borders(general_borders);
		borders.emplace_back(0);

		for (uint32_t i = 0; i < general_borders.size() - 1; i++) {
			borders.emplace_back(
				random_between(general_borders[i], general_borders[i + 1] - 1));
		}
		borders.emplace_back(obj.num_pages);
	}

	void
	convert_borders_to_ranges(
		std::vector<uint64_t> &borders)
	{
		for (uint32_t i = 0; i < borders.size() - 1; ++i) {
			ranges.emplace_back(borders[i], borders[i + 1] - 1);
		}
	}

	void
	make_random_partition()
	{
		std::vector<uint64_t> borders;
		create_borders(borders);
		convert_borders_to_ranges(borders);
	}

	void
	print_partition()
	{
		printf("| PARTITION:\t| ");
		for (const auto &range : ranges) {
			printf("%3d -- %3d", range.first, range.second);
		}
		printf("%*s|\n", 30, "");
		for (auto &m : mappings) {
			m.print_mapping();
		}
	}

	// Creation:

	void
	create_seq(std::vector<uint32_t> &seq)
	{
		seq.emplace_back(0);
		for (uint32_t i = 1; i < num_mappings; i++) {
			switch (topo) {
			case chain:
				seq.emplace_back(i);
				break;

			case random:
				seq.emplace_back(random_between(0, i));
				break;

			case star:
				seq.emplace_back(0);
				break;

			case ternary:
				seq.emplace_back(i / 3);
				break;

			default:
				throw std::runtime_error("create_seq: topology undefined");
				break;
			}
		}
		T_LOG("topology: %s", topo_to_string().c_str());
	}

	void
	allocate_buffer(
		uint64_t num_pages_to_alloc)
	{
		// buffers.emplace_back((char *)malloc((obj.num_pages + 1) * PAGE_SIZE)); // One extra page for a gap
		mach_vm_address_t buff = 0;
		kern_return_t kr = mach_vm_allocate(mach_task_self(), &buff, num_pages_to_alloc * PAGE_SIZE, TRUE);
		if (kr != KERN_SUCCESS) {
			throw std::runtime_error("Failed to allocate buffer in object #" + std::to_string(obj.id) + "\n");
		}
		buffers.push_back((char *)buff);
	}

	void
	initialize_partition_buffers()
	{
		for (auto &range : ranges) {
			allocate_buffer(range.second - range.first + 2);
		}
	}

	MappingArgs
	initialize_basic_args()
	{
		MappingArgs args;
		args.arg_src_address = obj.src;
		args.arg_copy = is_cow;
		args.arg_flags = mpng_flags;
		return args;
	}

	void
	map_by_seq(std::vector<uint32_t> &seq)
	{
		// First mapping of the source object:
		MappingArgs args = initialize_basic_args();
		allocate_buffer(obj.num_pages + 1);
		args.arg_target_address = (mach_vm_address_t)(buffers[0] + PAGE_SIZE);
		args.arg_mapping_size = obj.num_pages * PAGE_SIZE;
		mappings.emplace_back(Mapping(1, 0, args, obj.fd));

		// Re-mappings of the first mappings, according to the given seqence:
		for (uint32_t i = 1; i < num_mappings; i++) {
			allocate_buffer(obj.num_pages + 1);
			args.arg_src_address = mappings[seq[i - 1]].args.arg_target_address;
			args.arg_target_address = (mach_vm_address_t)(buffers[i]);
			mappings.emplace_back(Mapping(i + 1, 0, args, obj.fd));
			mappings[seq[i - 1]].add_child(&mappings[i]);
			mappings[i].set_src_mapping(mappings[seq[i - 1]]);
		}
		mappings[0].print_as_tree();
	}

	/* Mode 1 - maps parts of the object to parts of the (only) buffer. Every page is mapped exactly once. */
	void
	map_by_random_partition()
	{
		make_random_partition();
		initialize_partition_buffers();
		MappingArgs args = initialize_basic_args();
		for (uint32_t i = 0; i < num_mappings; i++) {
			args.arg_target_address = (mach_vm_address_t)(buffers[i] + PAGE_SIZE);
			args.arg_mapping_size = (ranges[i].second - ranges[i].first + 1) * PAGE_SIZE;
			mappings.emplace_back(Mapping(i + 1, ranges[i].first, args, obj.fd));
		}
	}

	/* Modes 2,4 - maps the entire object to different buffers (which all have the same size as the object). */
	void
	map_one_to_many(
		bool extra)
	{
		uint32_t num_pages_for_gaps = extra ? 2 : 1;
		MappingArgs args = initialize_basic_args();
		for (uint32_t i = 0; i < num_mappings; i++) {
			allocate_buffer(obj.num_pages + num_pages_for_gaps);
			args.arg_target_address = (mach_vm_address_t)(buffers[i] + PAGE_SIZE * num_pages_for_gaps);
			args.arg_mapping_size = obj.num_pages * PAGE_SIZE;
			mappings.emplace_back(Mapping(i + 1, 0, args, obj.fd));
		}
	}

	/* Mode 3 - maps the source object in a certain CoW-topology, based on the given sequence. */
	void
	map_topo()
	{
		std::vector<uint32_t> seq;
		create_seq(seq);
		map_by_seq(seq);
	}

	void
	map()
	{
		switch (policy) {
		case MappingPolicy::RandomPartition:
			map_by_random_partition();
			break;
		case MappingPolicy::OneToMany:
			map_one_to_many(false);
			break;
		case MappingPolicy::Overwrite:
			map_one_to_many(true);
			break;
		case MappingPolicy::Topology:
			num_mappings *= 4;
			mappings.reserve(num_mappings);
			topo = static_cast<topology>((obj.id - 1) % 4); // Each object (out of every 4 consecutive objects) will be remapped in a different CoW topology.
			map_topo();
			break;
		default:
			break;
		}
	}

	void
	set_srcs()
	{
		for (uint32_t i = 1; i < mappings.size(); i++) {
			mappings[i].set_src_mapping(mappings[i - 1]);
		}
	}

	/* Overwrites the first n/x pages of each mapping */
	void
	overwrite_mappings()
	{
		uint64_t num_pages_to_overwrite = obj.num_pages / overwrite_denom;
		MappingArgs args = initialize_basic_args();
		for (uint32_t i = 0; i < num_mappings; i++) {
			args.arg_target_address = (mach_vm_address_t)(buffers[i] + PAGE_SIZE);
			args.arg_mapping_size = num_pages_to_overwrite * PAGE_SIZE;
			mappings.emplace_back(Mapping(2 * i + 1, 0, args, obj.fd));
			mappings[i].fix_overwritten_mapping(num_pages_to_overwrite);
		}
		std::sort(mappings.begin(), mappings.end(), Mapping::compare_by_id);
		set_srcs(); // set the src (parent) lock for each newly created mapping to facilitate op_de_re_allocate().
	}

	// "User space" validation:

	bool
	validate_sum()
	{
		uint64_t sum = 0;

		for (const auto &mapping : mappings) {
			sum += mapping.num_pages;
		}
		if (sum != obj.num_pages) {
			return false;
		}
		return true;
	}

	bool
	validate_consecutiveness()
	{
		for (int i = 0; i < mappings.size() - 1; i++) {
			if (mappings[i].offset_in_pages + mappings[i].num_pages !=
			    mappings[i + 1].offset_in_pages) {
				return false;
			}
		}
		return true;
	}

	bool
	validate_start_and_end()
	{
		for (int i = 0; i < mappings.size() - 1; i++) {
			if (mappings[i].offset_in_pages + mappings[i].num_pages !=
			    mappings[i + 1].offset_in_pages) {
				return false;
			}
		}
		return true;
	}

	bool
	validate_all_sizes()
	{
		for (const auto &mapping : mappings) {
			if (mapping.num_pages != obj.num_pages) {
				return false;
			}
		}
		return true;
	}

	bool
	validate_partition()
	{
		return validate_sum() && validate_consecutiveness() && validate_start_and_end();
	}

	bool
	validate_one_to_many()
	{
		return validate_all_sizes();
	}

	bool
	validate_user_space()
	{
		switch (policy) {
		case MappingPolicy::RandomPartition:
			return validate_partition();
			break;
		case MappingPolicy::OneToMany:
			return validate_one_to_many();
			break;
		default:
			return true;
			break;
		}
	}

	// Miscellaneous:

	void
	set_flags(
		uint32_t flags)
	{
		mpng_flags = flags;
	}

	void
	set_is_cow(
		bool _is_cow)
	{
		is_cow = _is_cow;
	}

	void
	print_all_mappings()
	{
		for (auto &mpng : mappings) {
			mpng.print_mapping();
		}
	}

	// Data members:
	uint32_t num_mappings = 4;
	static inline uint32_t overwrite_denom = 2;
	/**
	 * Sets the part to overwrite in case MappingsManager::policy==MappingPolicy::Overwrite.
	 * It's the same for all of the mappings and has to be visible outside of the class for logging purposes. Therefore it's static.
	 */
	Object obj;
	std::vector<Mapping> mappings;
	MappingPolicy policy = MappingPolicy::OneToMany;
	std::vector<char *> buffers;
	std::vector<std::pair<uint32_t, uint32_t> > ranges;
	uint32_t mpng_flags = 0;
	bool is_cow = false;
	topology topo = topology::random;
};

class Memory
{
	using vm_op = std::function<bool (Mapping *)>;

public:
	// Member functions:

	// Creation:

	int
	create_objects(
		uint32_t num_objects, uint64_t obj_size, MappingPolicy policy, bool is_file, bool is_cow, bool slow_paging)
	{
		for (uint32_t i = 1; i <= num_objects; i++) {
			Object o(i, obj_size);
			if (o.create_source(is_file, slow_paging) == 0) {
				managers.emplace_back(std::make_unique<MappingsManager>(o, policy));
			} else {
				throw std::runtime_error("Error creating source object #" + std::to_string(i) + "\n");
			}
		}
		return 0;
	}

	void
	create_mappings(
		uint32_t flags, bool is_cow)
	{
		for (auto &mngr : managers) {
			mngr->set_flags(flags);
			mngr->set_is_cow(is_cow);
			mngr->map();
		}
	}

	void
	close_all_files()
	{
		for (auto &mngr : managers) {
			mngr->obj.close_file();
		}
	}

	// Thread-related operations:

	bool
	run_op_on_all_mappings(
		const std::pair<vm_op, std::string> *op, uint32_t op_idx)
	{
		for (auto &mngr : managers) {
			for (auto &m : mngr->mappings) {
				if (m.run_op(op)) {
					op_status_counters[op_idx].success++;
				} else {
					op_status_counters[op_idx].fail++;
				}
			}
		}
		return true;
	}

	void
	num2op(
		std::pair<vm_op, std::string> *op, uint32_t thread_number)
	{
		op->first  = Mapping::ops[thread_number % Mapping::ops.size()].first;
		op->second = Mapping::ops[thread_number % Mapping::ops.size()].second;
	}

	void
	print_thread_started(
		uint32_t thread_number, std::string thread_name)
	{
		uint32_t allowed_prints = Mapping::ops.size() * 3;
		if (thread_number < allowed_prints) {
			T_LOG("Starting thread: %s", thread_name.c_str());
		} else if (thread_number == allowed_prints) {
			T_LOG("...\n");
		}
		// Else: we've printed enough, don't make a mess on the console
	}

	std::future<void>
	start_thread(
		uint32_t thread_number,
		int32_t cpu)
	{
		uint32_t op_name_length = 16; // Just the length of the longest op name, for nicer printing of op_count
		std::pair<vm_op, std::string> operation;
		std::string thread_name;
		uint32_t thread_number_remainder = thread_number / Mapping::ops.size();
		num2op(&operation, thread_number);
		std::string operation_name_aligned = operation.second; // For nice printing only
		if (operation_name_aligned.length() < op_name_length) {
			operation_name_aligned = operation_name_aligned + std::string(op_name_length - operation_name_aligned.length(), ' '); // Pad if shorter than op_name_length
		}
		thread_name = operation_name_aligned + " #" + std::to_string(thread_number_remainder + 1);

		print_thread_started(thread_number, thread_name);

		return std::async(std::launch::async, [ =, this]() { /* lambda: */
			pthread_setname_np(thread_name.c_str());

			if (cpu != -1) {
			        pin_thread_to_cpu(cpu);
			}

			while (runner.state != TestRuntime::error &&
			runner.state != TestRuntime::complete) {
			        if (runner.state == TestRuntime::running) {
			                bool running = this->run_op_on_all_mappings(&operation, thread_number % Mapping::ops.size());
			                if (!running) {
			                        break;
					}
				}
			}
		});
	}

	std::future<void>
	start_interrupter(
		uint32_t thread_number, int32_t cpu, InterrupterParams const &params)
	{
		T_QUIET; T_ASSERT_NE(cpu, -1, "Interrupters are designed to run on specific CPUs.  No CPU specified.");

		return std::async(std::launch::async, [ =, this, &params] {
			std::string threadname = "Interrupter #" + std::to_string(thread_number);
			pthread_setname_np(threadname.c_str());

			pin_thread_to_cpu(cpu);
			make_highpriority(params);

			while (runner.state != TestRuntime::error &&
			runner.state != TestRuntime::complete) {
			        auto wait_time = std::chrono::microseconds(std::geometric_distribution<unsigned int>(params.interrupter_probability)(gen));
			        auto busy_time = std::chrono::microseconds(random_between(params.minimum_busy_time_us, params.maximum_busy_time_us));

			        std::this_thread::sleep_for(wait_time);

			        if (runner.state == TestRuntime::running) {
			                auto deadline = std::chrono::system_clock::now() + busy_time;
			                while (std::chrono::system_clock::now() < deadline) {
					}
			                interrupter_did_work++;
			                interrupter_work_done += busy_time;
				}
			}
		});
	}

	void
	start_ops(
		uint32_t num_threads, std::vector<bool> & used_cpus)
	{
		for (uint32_t i = 0; i < Mapping::ops.size(); i++) {
			op_status_counters.emplace_back(0, 0);
		}

		for (uint32_t i = 0; i < num_threads * Mapping::ops.size(); i++) {
			uint32_t cpu = random_between(0, used_cpus.size() - 1);
			used_cpus[cpu] = true;
			futures.emplace_back(start_thread(i, cpu));
		}
	}

	void
	start_ops(
		uint32_t num_threads)
	{
		for (uint32_t i = 0; i < Mapping::ops.size(); i++) {
			op_status_counters.emplace_back(0, 0);
		}

		for (uint32_t i = 0; i < num_threads * Mapping::ops.size(); i++) {
			futures.emplace_back(start_thread(i, -1 /* no specific CPU */));
		}
	}

	void
	start_interrupters(InterrupterParams const &params, std::vector<bool> const & used_cpus)
	{
		T_LOG("Starting real-time interrupters");
		T_LOG("Interrupter expected wait time: %uus", (unsigned int)(1.0 / params.interrupter_probability));
		T_LOG("Interrupter busy time: [%uus, %uus]", params.minimum_busy_time_us, params.maximum_busy_time_us);
		unsigned int thread_number = 0;
		for (unsigned int cpu = 0; cpu < used_cpus.size(); cpu++) {
			// Spread the interrupters across all used CPUs
			if (used_cpus[cpu]) {
				futures.emplace_back(start_interrupter(thread_number++, cpu, params));
			}
		}
	}

	void
	join_threads()
	{
		for (auto &f : futures) {
			f.get(); // This replaces thread.join() in order to propogate the exceptions raised from non main threads
		}
	}

	// Miscellaneous:

	void
	print_mem_layout()
	{
		T_LOG("\nmemory layout:");
		uint32_t allowed_prints = 3;
		for (uint32_t i = 0; i < managers.size() && i < allowed_prints; i++) {
			managers[i]->obj.print_object();
			managers[i]->print_all_mappings();
		}
		T_LOG(" -----------------------------------------------------------------------------");
		T_LOG("...\n");
	}

	void
	print_op_counts()
	{
		for (uint32_t i = 0; i < Mapping::ops.size(); i++) {
			T_LOG("%16s: successes %7d :|: fails: %7d", Mapping::ops[i].second.c_str(), op_status_counters[i].success, op_status_counters[i].fail);
		}
	}

	void
	print_interrupter_counts()
	{
		T_LOG("Interrupter ran %" PRIu64 " times\n", interrupter_did_work);
		T_LOG("Interrupter ran for %" PRIu64 "ms\n", std::chrono::duration_cast<std::chrono::milliseconds>(interrupter_work_done).count());
	}

	void
	overwrite_all()
	{
		for (auto &mngr : managers) {
			mngr->overwrite_mappings();
		}
	}

	bool
	validate()
	{
		for (auto &mngr : managers) {
			if (!mngr->validate_user_space()) {
				return false;
			}
		}
		return true;
	}

	void
	print_test_result()
	{
		T_LOG("\ninner validation: OBJECTS AND MAPPINGS APPEAR %s", validate() ? "AS EXPECTED" : "*NOT* AS EXPECTED");
	}

	// Data members:

	std::vector<std::unique_ptr<MappingsManager> > managers;
	std::vector<std::future<void> > futures;
	static inline std::vector<struct status_counters> op_status_counters;

	uint64_t interrupter_did_work = 0;
	std::chrono::nanoseconds interrupter_work_done{0};
};

int32_t
available_cpus()
{
	int32_t ncpus = 0;
	size_t ncpu_size = sizeof(ncpus);
	int ret = sysctlbyname("hw.ncpu", &ncpus, &ncpu_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(hw.ncpu)");
	return ncpus;
}

uint32_t
run_test(
	const TestParams &tp)
{
	Memory memory;
	uint32_t status;

	int src_created_successfully = memory.create_objects(tp.num_objects, tp.obj_size, tp.policy, tp.is_file, tp.is_cow, tp.slow_paging);
	if (src_created_successfully != 0) {
		throw std::runtime_error("problem with creating source objects\n");
	}

	memory.create_mappings(tp.mpng_flags, tp.is_cow);
	memory.print_mem_layout();

	if (tp.policy == MappingPolicy::Overwrite) {
		memory.overwrite_all();
		T_LOG("1 / %d of each mapping got overwritten\n", MappingsManager::overwrite_denom);
		memory.print_mem_layout();
	}

	if (tp.enable_interrupters) {
		T_LOG("Enabling high-priority workloads.");
		T_QUIET; T_ASSERT_TRUE(is_cpu_pinning_supported(), "CPU pinning not supported.  Add `enable_skstb=1` to boot-args and run the test as root");

		int32_t ncpus = available_cpus();
		T_LOG("Found %" PRId32 " CPUs\n", ncpus);

		std::vector<bool> used_cpus(ncpus);
		memory.start_ops(tp.num_threads, used_cpus);

		auto cpus_used = std::count_if(
			std::begin(used_cpus),
			std::end(used_cpus),
			[](auto count) {
			return count > 0;
		});

		T_LOG("Scheduled worker threads on %d CPUs", (int)cpus_used);

		memory.start_interrupters(tp.interrupter_params, used_cpus);
	} else {
		memory.start_ops(tp.num_threads);
	}

	status = runner.wait_for_status(tp.runtime_secs);

	memory.join_threads();

	memory.print_op_counts();

	if (tp.enable_interrupters) {
		memory.print_interrupter_counts();
	}

	memory.close_all_files();
	memory.print_test_result();

	T_LOG("test finished\n");
	return status;
}

void
try_catch_test(TestParams &tp)
{
	try
	{
		if (run_test(tp)) {
			T_FAIL("Test failed");
		} else {
			T_PASS("Test passed");
		}
	}

	catch (const std::runtime_error &e)
	{
		T_FAIL("Caught a runtime error: %s", e.what());
	}
}

static unsigned int
read_integer(const char *arg)
{
	unsigned int result = strtoul(arg, NULL, 10);
	if (!result && errno) {
		T_ASSERT_FAIL("argument should be an integer");
	}
	return result;
}

void
print_help()
{
	printf("\n\nUsage: <path_to_executable>/vm_stress [<test selection>] -- [-i] [-w <wait_time>] [-b <min_busy_time> <max_busy_time>]\n");
	printf("  -i                 Enable high-priority workloads.\n");
	printf("  -w <wait_time>     Time in-between busy work for high-priority workloads in us.\n");
	printf("                     The actual wait time is randomized around this expected value.\n");
	printf("  -b <min_busy_time> <max_busy_time>\n");
	printf("                     Set the bounds for random busy-work done by high-priority workloads in us.\n");
}

static void
apply_interrupter_args(int &argc, char * const *&argv,
    InterrupterParams &ip, bool &enable)
{
	for (; argc > 0 && argv[0] != NULL; argc--, argv++) {
		const char *arg = argv[0];
		if (strcmp(arg, "-h") == 0) {
			print_help();
			exit(0);
		} else if (strcmp(arg, "-i") == 0) {
			T_LOG("Enabling interrupters");
			enable = true;
			ip = default_interrupter_params;
		} else if (strcmp(arg, "-w") == 0) {
			if (argc < 2) {
				T_ASSERT_FAIL(
					"-w takes the expected wait time for the interrupter in us");
			}
			unsigned int expected_wait_time_us = read_integer(argv[1]);
			ip.interrupter_probability =
			    1.0f / expected_wait_time_us;

			argc -= 1;
			argv += 1;
		} else if (strcmp(arg, "-b") == 0) {
			if (argc < 3) {
				T_ASSERT_FAIL("-b requires min and max arguments");
			}
			ip.minimum_busy_time_us = read_integer(argv[1]);
			ip.maximum_busy_time_us = read_integer(argv[2]);

			argc -= 2;
			argv += 2;
		} else {
			break;
		}
	}
}

static void
try_catch_test_args(int argc, char * const *argv, TestParams &tp)
{
	apply_interrupter_args(argc, argv, tp.interrupter_params, tp.enable_interrupters);
	try_catch_test(tp);
}

void
print_config_help()
{
	printf("\n\nUsage: <path_to_executable>/vm_stress config -- <mapping_policy> <num_objects> <obj_size> <runtime_secs> <num_threads> <is_cow> <is_file> [-s]\n\n");

	printf("  <num_objects>      Number of objects the test will create and work on\n");
	printf("  <obj_size>         Size of each object (>=16)\n");
	printf("  <runtime_secs>     Test duration in seconds\n");
	printf("  <num_threads>      Number of threads to use for each operation\n");
	printf("  <mapping_policy>   Policy for mapping (part/one_to_many/over/topo)\n");
	printf("  <is_cow>           Copy-on-write flag (0 or 1)\n");
	printf("  <is_file>          File flag (0 or 1)\n\n");
}

void
string_to_policy(
	MappingPolicy &policy, std::string policy_str)
{
	const std::map<std::string, MappingPolicy> string_to_policy =
	{
		{"part", MappingPolicy::RandomPartition},
		{"one_to_many", MappingPolicy::OneToMany},
		{"over", MappingPolicy::Overwrite},
		{"topo", MappingPolicy::Topology},
	};

	auto it = string_to_policy.find(policy_str);

	if (it != string_to_policy.end()) {
		policy = it->second;
	} else {
		throw std::runtime_error("Invalid policy string: \"" + policy_str + "\"\n");
	}
}

T_DECL(config, "configurable", T_META_ENABLED(false) /* rdar://142726486 */)
{
	bool slow_paging = false;
	int opt;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0) {
			slow_paging = true;
		} else if (strcmp(argv[i], "-h") == 0) {
			print_config_help();
			T_PASS("help configs");
			return;
		}
	}

	InterrupterParams ip = default_interrupter_params;
	bool enable_interrupters = false;
	apply_interrupter_args(argc, argv, ip, enable_interrupters);

	if (argc == 0) {
		printf("\n\n\nNo arguments for configurable test, assuming intention was to skip it.\n\n\n");
		T_PASS("config - no args given");
		return;
	}

	if (argc != 7 && argc != 8) {
		printf("\n\n\nWrong number of arguments.\n");
		printf("Usage: <path_to_executable>/vm_stress config -- <mapping_policy> <num_objects> <obj_size> <runtime_secs> <num_threads> <is_cow> <is_file>\nPolicies: part/one_to_many/over/topo\n\n");
		printf("Run \"<path_to_executable>/vm_stress config -- -h\" for more info\n\n\n");
		T_PASS("config - not enough/too many args");
		return;
	}

	std::string policy_str(argv[0]);
	MappingPolicy policy;
	string_to_policy(policy, policy_str);

	uint32_t num_objects = strtoul(argv[1], NULL, 0);

	uint64_t obj_size = strtoull(argv[2], NULL, 0); // In pages

	if (obj_size < 16) {
		throw std::runtime_error("obj_size must be more than 16\n");
	}

	uint32_t runtime_secs = strtoul(argv[3], NULL, 0);

	uint32_t num_threads = strtoul(argv[4], NULL, 0);

	bool is_cow = strtoul(argv[5], NULL, 0);

	bool is_file = strtoul(argv[6], NULL, 0);

	TestParams params = {
		.num_objects = num_objects,
		.obj_size = obj_size,
		.runtime_secs = runtime_secs,
		.num_threads = num_threads,
		.policy = policy,
		.is_cow = is_cow,
		.is_file = is_file,
		.slow_paging = slow_paging,
		.enable_interrupters = enable_interrupters,
		.interrupter_params = ip,
	};

	try_catch_test(params);
}

T_DECL(vm_stress1, "partitions")
{
	TestParams params = {
		.num_objects = 5,
		.obj_size = 32,
		.runtime_secs = 3,
		.num_threads = 2,
		.policy = MappingPolicy::RandomPartition,
		.is_cow = true,
		.is_file = true,
		.slow_paging = false};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress2, "cow topologies")
{
	TestParams params = {
		.num_objects = 10,
		.obj_size = 32,
		.runtime_secs = 4,
		.num_threads = 4,
		.policy = MappingPolicy::Topology,
		.is_cow = true,
		.is_file = true,
		.slow_paging = false};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress3, "overwrite")
{
	TestParams params = {
		.num_objects = 10,
		.obj_size = 16,
		.runtime_secs = 3,
		.num_threads = 2,
		.policy = MappingPolicy::Overwrite,
		.is_cow = true,
		.is_file = true,
		.slow_paging = false};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress4, "partitions - not file-backed")
{
	TestParams params = {
		.num_objects = 5,
		.obj_size = 32,
		.runtime_secs = 3,
		.num_threads = 2,
		.policy = MappingPolicy::RandomPartition,
		.is_cow = true,
		.is_file = false,
		.slow_paging = false};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress5, "cow topologies - not file-backed")
{
	TestParams params = {
		.num_objects = 10,
		.obj_size = 32,
		.runtime_secs = 4,
		.num_threads = 4,
		.policy = MappingPolicy::Topology,
		.is_cow = true,
		.is_file = false,
		.slow_paging = false};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress6, "overwrite - not file-backed")
{
	TestParams params = {
		.num_objects = 10,
		.obj_size = 16,
		.runtime_secs = 3,
		.num_threads = 2,
		.policy = MappingPolicy::Overwrite,
		.is_cow = true,
		.is_file = false,
		.slow_paging = false};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress7, "one to many - not CoW and not file-backed")
{
	TestParams params = {
		.num_objects = 5,
		.obj_size = 100,
		.runtime_secs = 10,
		.num_threads = 3,
		.policy = MappingPolicy::OneToMany,
		.is_cow = false,
		.is_file = false,
		.slow_paging = false,
	};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress8, "cow topologies - with high-priority-interrupters")
{
	TestParams params = {
		.num_objects = 10,
		.obj_size = 32,
		.runtime_secs = 4,
		.num_threads = 4,
		.policy = MappingPolicy::Topology,
		.is_cow = true,
		.is_file = true,
		.slow_paging = false,
		.enable_interrupters = true,
		.interrupter_params = default_interrupter_params
	};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress9, "cow topologies - not file-backed - with high-priority-interrupters")
{
	TestParams params = {
		.num_objects = 10,
		.obj_size = 32,
		.runtime_secs = 4,
		.num_threads = 4,
		.policy = MappingPolicy::Topology,
		.is_cow = true,
		.is_file = false,
		.slow_paging = false,
		.enable_interrupters = true,
		.interrupter_params = default_interrupter_params
	};

	try_catch_test_args(argc, argv, params);
}

T_DECL(vm_stress_hole, "Test locking of ranges with holes in them.")
{
	uint32_t num_secs = 5;
	uint32_t half_of_num_mappings = 5; // To ensure num_mappings is an even number.
	std::vector<mach_vm_address_t> mappings;
	mach_vm_address_t addr0 = 0;
	mach_vm_allocate(mach_task_self(), &addr0, PAGE_SIZE, TRUE);
	mappings.emplace_back(addr0);
	for (uint32_t i = 1; i < half_of_num_mappings * 2; i++) {
		mach_vm_address_t addri = addr0 + PAGE_SIZE * 2 * i;
		mach_vm_allocate(mach_task_self(), &addri, PAGE_SIZE, FALSE);
		mappings.emplace_back(addri);
	}
	auto start_time = std::chrono::steady_clock::now();
	auto end_time = start_time + std::chrono::seconds(num_secs);
	uint32_t inheritance = 1;
	int err = 0;
	while (std::chrono::steady_clock::now() < end_time) {
		for (uint32_t i = 0; i < half_of_num_mappings * 2; i += 2) {
			if ((err = minherit((void *)mappings[i], 2 * PAGE_SIZE, inheritance % 2)) != 0) {
				break;
			}
		}
		if (err < 0) {
			break;
		}
		inheritance++;
	}
	T_QUIET;
	T_ASSERT_EQ_INT(err, 0, "all calls to minherit returned successfully");
	if (err == 0) {
		T_PASS("HOLE LOCKING PASSED");
	} else {
		T_FAIL("SOME ERROR IN MINHERIT, err=%d", err);
	}
}
