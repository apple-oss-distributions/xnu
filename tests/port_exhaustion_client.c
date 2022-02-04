#include <stdio.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static inline mach_port_type_t
get_port_type(mach_port_t mp)
{
	mach_port_type_t type = 0;
	mach_port_type(mach_task_self(), mp, &type);
	return type;
}

int
main()
{
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t retval = KERN_SUCCESS;

	mach_port_t task = mach_task_self();

	printf("Starting the receive right allocation loop\n");
	int i = 0;
	while (!retval) {
		retval = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
		assert(retval == 0);
		//printf("%d. allocate a port=[%d]\n", i, port);
		assert(get_port_type(port) == MACH_PORT_TYPE_RECEIVE);
		i++;
	}

	exit(1);
}
