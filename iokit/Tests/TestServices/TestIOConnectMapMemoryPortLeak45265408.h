#ifndef _IOKIT_TESTIOCONNECTMAPMEMORYPORTLEAK45265408_H_
#define _IOKIT_TESTIOCONNECTMAPMEMORYPORTLEAK45265408_H_

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#if DEVELOPMENT || DEBUG

class TestIOConnectMapMemoryPortLeak45265408 : public IOService {
	OSDeclareDefaultStructors(TestIOConnectMapMemoryPortLeak45265408)

public:
	virtual bool start(IOService *provider) override;
};

class TestIOConnectMapMemoryPortLeak45265408UserClient : public IOUserClient {
	OSDeclareDefaultStructors(TestIOConnectMapMemoryPortLeak45265408UserClient);

public:
	// IOService overrides
	virtual bool start(IOService *provider) override;
	virtual void stop(IOService *provider) override;

	// IOUserClient overrides
	virtual IOReturn clientClose() override;
	virtual IOReturn clientMemoryForType(UInt32 type, IOOptionBits *flags, IOMemoryDescriptor **memory) override;
private:
	IOBufferMemoryDescriptor *  sharedMemory;
};

#endif /* DEVELOPMENT || DEBUG */

#endif /* _IOKIT_TESTIOCONNECTMAPMEMORYPORTLEAK45265408_H_ */
