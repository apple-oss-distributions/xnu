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

class TestIODeviceMemoryRosettaUserClient : public IOUserClient2022 {
	OSDeclareDefaultStructors(TestIODeviceMemoryRosettaUserClient);


public:
	virtual bool start(IOService * provider) override;
	virtual IOReturn clientClose() override;
	IOReturn externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args) override;
	IOReturn
	externalMethodDispatched(IOExternalMethodArguments * args);
};

#endif /* (DEVELOPMENT || DEBUG) && XNU_TARGET_OS_OSX */

#endif /* _IOKIT_TESTIODEVICEMEMORYROSETTA_H_ */
