/* * Copyright (c) 2019 Apple Inc. All rights reserved. */

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>


class IOKitDiagnosticsClient : public IOUserClient2022
{
	OSDeclareDefaultStructors(IOKitDiagnosticsClient);

public:
	static  IOUserClient * withTask(task_t owningTask);
	virtual IOReturn       clientClose(void) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       setProperties(OSObject * properties) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args) APPLE_KEXT_OVERRIDE;
};
