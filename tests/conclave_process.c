#include <stdio.h>
#include <sys/sysctl.h>
#include <string.h>

int
main(int argc, char *argv[])
{
	char conclave_id[256];
	size_t conclave_id_size = 256;
	printf("Doing Sysctl for getting conclave name\n");
	int ret = sysctlbyname("kern.task_conclave", conclave_id, &conclave_id_size, NULL, 0);
	if (ret != 0) {
		printf("sysctlbyname for kern.task_conclave returned %d \n", ret);
		return 2;
	}

	if (strncmp(argv[1], conclave_id, 256) == 0) {
		printf("Spawned with correct conclave id %s\n", conclave_id);
		return 0;
	}

	printf("Expected conclave id %s but spawned with %s\n", argv[1], conclave_id);
	return 1;
}
