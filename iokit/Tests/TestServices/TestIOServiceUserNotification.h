#ifndef _IOKIT_TESTIOSERVICEUSERNOTIFICATION_H_
#define _IOKIT_TESTIOSERVICEUSERNOTIFICATION_H_

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

#if DEVELOPMENT || DEBUG

class TestIOServiceUserNotification : public IOService {
	OSDeclareDefaultStructors(TestIOServiceUserNotification);

public:
	virtual bool start(IOService *provider) override;
};

class TestIOServiceUserNotificationUserClient : public IOUserClient {
	OSDeclareDefaultStructors(TestIOServiceUserNotificationUserClient);

public:
	virtual IOReturn clientClose() override;
	IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments * args,
	    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference) override;
};

#endif /* DEVELOPMENT || DEBUG */

#endif /* _IOKIT_TESTIOSERVICEUSERNOTIFICATION_H_ */
