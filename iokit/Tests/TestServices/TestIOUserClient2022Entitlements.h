#ifndef _IOKIT_TESTIOUSERCLIENT2022ENTITLEMENTS_H_
#define _IOKIT_TESTIOUSERCLIENT2022ENTITLEMENTS_H_

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

#if (DEVELOPMENT || DEBUG)

class TestIOUserClient2022Entitlements : public IOService {
	OSDeclareDefaultStructors(TestIOUserClient2022Entitlements);

public:
	virtual bool start(IOService *provider) override;
};

class TestIOUserClient2022EntitlementsUserClient : public IOUserClient2022 {
	OSDeclareDefaultStructors(TestIOUserClient2022EntitlementsUserClient);


public:
	virtual bool start(IOService * provider) override;
	virtual IOReturn clientClose() override;
	IOReturn externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args) override;
	static IOReturn        extBasicMethod(OSObject * target, void * reference, IOExternalMethodArguments * arguments);
	static IOReturn        extPerSelectorCheck(OSObject * target, void * reference, IOExternalMethodArguments * arguments);
};

#endif /* (DEVELOPMENT || DEBUG) */

#endif /* _IOKIT_TESTIOUSERCLIENT2022ENTITLEMENTS_H_ */
