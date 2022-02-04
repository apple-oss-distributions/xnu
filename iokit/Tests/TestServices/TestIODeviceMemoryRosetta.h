#ifndef _IOKIT_TESTIODEVICEMEMORYROSETTA_H_
#define _IOKIT_TESTIODEVICEMEMORYROSETTA_H_

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

#if (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX

class TestIODeviceMemoryRosetta : public IOService {
	OSDeclareDefaultStructors(TestIODeviceMemoryRosetta);

public:
	virtual bool start(IOService *provider) override;
};

class TestIODeviceMemoryRosettaUserClient : public IOUserClient {
	OSDeclareDefaultStructors(TestIODeviceMemoryRosettaUserClient);

public:
	virtual IOReturn clientClose() override;
	IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments * args,
	    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference) override;
};

#endif /* (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX */

#endif /* _IOKIT_TESTIODEVICEMEMORYROSETTA_H_ */
