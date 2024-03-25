#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/attr.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#pragma clang diagnostic ignored "-Wformat-nonliteral"

static int verbose = 0;

#define PRINTF(...) \
    do {            \
	if (verbose) { \
	        printf(__VA_ARGS__); \
	}                               \
    } while (0)

#define ASSERT(cond, ...)       \
    if (!(cond)) {                \
	        printf(__VA_ARGS__); \
    }                           \

typedef struct {
	uint64_t graft_dir_id; // If this is 0, grafting will be performed on the parent directory of the graft file
	uint64_t flags;
} apfs_graft_params_t;

#define APFSIOC_GRAFT_AN_FS _IOW('J', 99, apfs_graft_params_t)
#define APFSIOC_UNGRAFT_AN_FS _IOW('J', 100, uint64_t)

#define MAIN_DIR "/tmp/"
// Force unmount
#define FUNMOUNT_IMAGE_NAME "TestImage.dmg"
#define FUNMOUNT_IMAGE MAIN_DIR FUNMOUNT_IMAGE_NAME
#define FUNMOUNT_VOL_NAME "TestImage"
#define FUNMOUNT_MOUNT_POINT "/Volumes/" FUNMOUNT_VOL_NAME "/"
#define FUNMOUNT_FILE_NAME "test.txt"
#define FUNMOUNT_FILE FUNMOUNT_MOUNT_POINT FUNMOUNT_FILE_NAME
// Ungraft
#define HOST_DMG MAIN_DIR "VmNoPagerHostMount.dmg"
#define HOST_MOUNT_POINT MAIN_DIR "TestVmNoPagerHostMount/"
#define GRAFT_MOUNT_POINT HOST_MOUNT_POINT "graft_mount_point/"
#define GRAFT_DMG_NAME "VmNoPagerGraftImage.dmg"
#define GRAFT_DMG GRAFT_MOUNT_POINT GRAFT_DMG_NAME
#define GRAFT_TMP_MOUNT_POINT MAIN_DIR "tmp_graft_mount_point/"
#define TEXT_FILE_NAME "graft_test_file.txt"
#define HOST_VOL_NAME "TestNoPagerHostVol"
#define GRAFT_VOL_NAME "TestNoPagerGraftVol"

static int
my_system(const char* cmd)
{
	char quiet_cmd[1024];

	snprintf(quiet_cmd, sizeof(quiet_cmd), "%s%s", cmd, verbose ? "" : " > /dev/null");
	PRINTF("Execute: '%s'\n", quiet_cmd);
	return system(quiet_cmd);
}

static int
exec_cmd(const char* fmt, ...)
{
	char cmd[512];

	va_list args;
	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);

	int retval = my_system(cmd);

	va_end(args);
	return retval;
}

static int
execute_and_get_output(char* buf, size_t len, const char* fmt, ...)
{
	char tmp[512];
	FILE* popen_stream;

	va_list args;
	va_start(args, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, args);
	va_end(args);

	PRINTF("Execute and get output: '%s'\n", tmp);
	popen_stream = popen(tmp, "r");
	if (popen_stream == NULL) {
		printf("popen for command `%s` failed\n", tmp);
	}
	if (fgets(buf, (int)len, popen_stream) == NULL) {
		pclose(popen_stream);
		printf("Getting output from popen for command `%s` failed\n", tmp);
	}
	pclose(popen_stream);

	return 0;
}

static int
disk_image_attach(const char* image_path)
{
	return exec_cmd("diskimagetool attach %s", image_path);
}

static int
disk_image_mount(const char* mount_point, const char* device_name)
{
	return exec_cmd("diskutil mount -mountPoint %s %s", mount_point, device_name);
}

static int
disk_image_unmount(const char* device_name)
{
	return exec_cmd("diskutil unmountDisk %s", device_name);
}

static int
disk_image_unmount_forced(const char* device_name)
{
	return exec_cmd("diskutil unmountDisk force %s", device_name);
}

static int
disk_image_eject(const char* device_name)
{
	disk_image_unmount_forced(device_name);
	return exec_cmd("diskutil eject %s", device_name);
}

static void
fork_and_crash(void(f_ptr)(char*, char*), char* file_path, char* device_identifier)
{
	pid_t pid = fork();
	if (pid == 0) {
		// Should induce a crash
		f_ptr(file_path, device_identifier);
	} else {
		int status;
		if (waitpid(pid, &status, 0) == -1) {
			printf("waitpid to wait for child(pid: '%d') failed", pid);
		}

		if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGBUS) {
			printf("Child process didn't get a SIGBUS\n");
		} else {
			PRINTF("Child process SIGBUS'd\n");
		}
	}
}

static void
read_and_cause_unmount_crash(char* file_path, char* device_identifier)
{
	int test_file_fd;

	if ((test_file_fd = open(file_path, O_RDWR)) == -1) {
		printf("couldn't open file '%s'\n", file_path);
	}

	char* mapped = mmap(0, 1024, PROT_WRITE, MAP_SHARED, test_file_fd, 0);;
	if (mapped == MAP_FAILED) {
		close(test_file_fd);
		printf("couldn't mmap file '%s', errno %d\n", file_path, errno);
	} else {
		PRINTF("mmap'd file: '%s'\n", file_path);
	}

	// force unmount
	ASSERT(!disk_image_eject(device_identifier), "Failed to force unmount device '%s'", device_identifier);
	mapped[0] = 'A'; // cause page fault and crash
	printf("Unexpectedly didn't crash after write (after force unmount)");

	close(test_file_fd);
}

static void
read_and_cause_ungraft_crash(char* file_path, __unused char* unused)
{
	int test_file_fd;
	int retval;

	if ((test_file_fd = open(file_path, O_RDWR)) == -1) {
		printf("couldn't open %s\n", file_path);
	}

	char* mapped = mmap(0, 1024, PROT_WRITE, MAP_SHARED, test_file_fd, 0);;
	if (mapped == MAP_FAILED) {
		close(test_file_fd);
		printf("couldn't mmap, errno %d\n", errno);
	} else {
		PRINTF("mmap'd file: '%s'\n", file_path);
	}

	// ungraft
	apfs_graft_params_t graft_params = {};
	retval = fsctl(GRAFT_MOUNT_POINT, APFSIOC_UNGRAFT_AN_FS, &graft_params, 0);
	PRINTF("fsctl ungraft result: %d\n", retval);

	PRINTF("child about to crash\n");
	mapped[0] = 'A'; // cause page fault and crash
	printf("Unexpectedly didn't crash after write (after ungraft)");
	close(test_file_fd);
}

static void
setup_unmount_image(char* disk_name, size_t len)
{
	ASSERT(!exec_cmd("hdiutil create -size 100m -fs apfs -volname %s %s", FUNMOUNT_VOL_NAME, FUNMOUNT_IMAGE), "Disk image creation failed (%s)\n", FUNMOUNT_IMAGE);
	ASSERT(!disk_image_attach(FUNMOUNT_IMAGE), "Attaching and mounting disk image during creation failed (%s)\n", FUNMOUNT_IMAGE);
	execute_and_get_output(disk_name, len, "diskutil list | grep %s | awk {'print $7'}", FUNMOUNT_VOL_NAME);
	ASSERT(strlen(disk_name) != 0, "disk_name is empty");
	ASSERT(!my_system("echo 'abcdefghijk' > " FUNMOUNT_FILE), "Creating file '%s' failed.\n", FUNMOUNT_FILE);
	ASSERT(!exec_cmd("diskutil eject %s", disk_name), "Disk image detach/eject during creation failed (%s)\n", disk_name);
}

static void
forced_unmount_crash_test(void)
{
	char device_identifier[128];

	setup_unmount_image(device_identifier, sizeof(device_identifier));
	ASSERT(!disk_image_attach(FUNMOUNT_IMAGE), "attaching and mounting image '%s' failed\n", FUNMOUNT_IMAGE);
	fork_and_crash(read_and_cause_unmount_crash, FUNMOUNT_FILE, device_identifier);

	// Cleanup
	my_system("rm -f " FUNMOUNT_IMAGE);
	disk_image_eject(device_identifier);
}

static void
create_disk_image(const char* image_path, const char* volume_name, bool use_gpt, char* device_name_out, size_t device_len, char* partition_name_out, size_t partition_len)
{
	char buf[512];
	char* device_name;
	char* end_ptr;
	char partition_name[32];

	// Create image
	ASSERT(!exec_cmd("diskimagetool create -size 100m -fs none %s", image_path), "Image creation at `%s` failed\n", image_path);

	// Attach
	ASSERT(!execute_and_get_output(buf, sizeof(buf), "diskimagetool attach -nomount %s", image_path), "Attaching image (nomount) at %s failed\n", image_path);
	ASSERT(strstr(buf, "/dev/disk"), "Didn't get expected device identifier after attaching. Got: `%s`\n", buf);
	if ((end_ptr = strchr(buf, '\n'))) {
		*end_ptr = '\0';
	}
	device_name = strdup(buf);
	strncpy(device_name_out, device_name, device_len);

	// Partition and format
	if (use_gpt) {
		ASSERT(!exec_cmd("mkutil partition %s --map GPT --type Apple_APFS", device_name), "partition failed\n");

		snprintf(partition_name, sizeof(partition_name), "%ss2", device_name);
		struct stat sb;
		if (stat(partition_name, &sb)) {
			ASSERT(errno == ENOENT, "Device `%s` exists, while we expect only the `s1` suffix to exist\n", partition_name);
			partition_name[strlen(partition_name) - 1] = '1';
		}
	} else {
		snprintf(partition_name, sizeof(partition_name), "%s", device_name);
	}
	ASSERT(!exec_cmd("newfs_apfs -v %s %s", volume_name, partition_name), "Formatting volume with APFS failed\n");

	// Grab the name for ungrafting later on
	ASSERT(!execute_and_get_output(buf, sizeof(buf), "diskutil list | grep '%s' | awk {'print $7'}", volume_name), "Getting parition name failed\n");
	if ((end_ptr = strchr(buf, '\n'))) {
		*end_ptr = '\0';
	}
	strncpy(partition_name_out, buf, partition_len);
}

static void
setup_host_image(char* device_identifier, size_t len)
{
	char partition_name[128];

	printf("Setting up host\n");
	create_disk_image(HOST_DMG, HOST_VOL_NAME, true /* use_gpt */, device_identifier, len, partition_name, sizeof(partition_name));
	my_system("mkdir -p " HOST_MOUNT_POINT);
	disk_image_mount(HOST_MOUNT_POINT, partition_name);
}

static void
setup_graft_image(char* device_identifier, size_t len)
{
	char partition_name[128];

	// Create graft image, mount it to create the text file, then unmount so it can be grafted
	printf("Setting up graft\n");
	my_system("mkdir -p " GRAFT_TMP_MOUNT_POINT);
	my_system("mkdir -p " GRAFT_MOUNT_POINT);
	create_disk_image(GRAFT_DMG, GRAFT_VOL_NAME, false /* use_gpt*/, device_identifier, len, partition_name, sizeof(partition_name));
	ASSERT(!disk_image_mount(GRAFT_TMP_MOUNT_POINT, partition_name), "Failed to mount partition `%s` before file creation\n", partition_name);
	ASSERT(!exec_cmd("echo 'fsafasfasdg' > %s", GRAFT_TMP_MOUNT_POINT TEXT_FILE_NAME), "Failed to create file %s\n", GRAFT_TMP_MOUNT_POINT TEXT_FILE_NAME);
	disk_image_unmount(GRAFT_TMP_MOUNT_POINT);

	// Graft
	apfs_graft_params_t graft_params = {};
	__unused uint64_t ungraft_params = 0;
	int retval = fsctl(GRAFT_DMG, APFSIOC_GRAFT_AN_FS, &graft_params, 0);
	PRINTF("fsctl graft result: %d\n", retval);
}

static void
cleanup_ungraft(char* graft_disk_identifier, char* host_disk_identifier)
{
	disk_image_eject(graft_disk_identifier);
	disk_image_eject(host_disk_identifier);
	my_system("rm -rf " GRAFT_TMP_MOUNT_POINT);
	my_system("rm -rf " HOST_MOUNT_POINT);
	my_system("rm -f " HOST_DMG);
}

static void
ungraft_crash_test(void)
{
	char host_disk_identifier[128];
	char graft_disk_identifier[128];

	setup_host_image(host_disk_identifier, sizeof(host_disk_identifier));
	setup_graft_image(graft_disk_identifier, sizeof(graft_disk_identifier));

	fork_and_crash(read_and_cause_ungraft_crash, GRAFT_MOUNT_POINT TEXT_FILE_NAME, host_disk_identifier);

	cleanup_ungraft(graft_disk_identifier, host_disk_identifier);
}

int
main(int argc, char** argv)
{
	if (argc < 2) {
		printf("Usage: test_vm_no_pager_helper 1|2 [-v]\n");
		exit(1);
	}

	__unused char* unused;
	int test_to_run = (int)strtol(argv[1], NULL, 10);
	if (errno == EINVAL) {
		printf("Bad test argument passed\n");
		exit(1);
	}

	if (geteuid() != 0) {
		PRINTF("Crash test not running as root\n");
		exit(1);
	}

	printf("running test %d\n", test_to_run);

	if (argc > 2) {
		printf("%s", argv[2]);
	}

	if (argc > 2 && strcmp(argv[2], "-v") == 0) {
		verbose = 1;
	}

	switch (test_to_run) {
	case 1:
		forced_unmount_crash_test();
		break;
	case 2:
		ungraft_crash_test();
		break;
	default:
		printf("Invalid test number passed'n");
		exit(1);
	}
}
