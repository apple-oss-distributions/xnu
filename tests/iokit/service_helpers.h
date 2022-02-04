#ifndef _XNU_TESTS_IOKIT_SERVICE_HELPERS_H_
#define _XNU_TESTS_IOKIT_SERVICE_HELPERS_H_

#include <IOKit/IOKitLib.h>

__BEGIN_DECLS

int IOTestServiceFindService(const char * name, io_service_t * serviceOut);

__END_DECLS

#endif /* _XNU_TESTS_IOKIT_SERVICE_HELPERS_H_ */
