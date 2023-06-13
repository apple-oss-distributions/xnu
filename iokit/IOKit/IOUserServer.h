/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */


#ifndef _IOUSERSERVER_H
#define _IOUSERSERVER_H

#include <IOKit/IORPC.h>

#define kIOUserServerClassKey  "IOUserServer"
#define kIOUserServerNameKey   "IOUserServerName"
#define kIOUserServerTagKey    "IOUserServerTag"
// the expected cdhash value of the userspace driver executable
#define kIOUserServerCDHashKey "IOUserServerCDHash"

#if DRIVERKIT_PRIVATE

enum{
	kIOKitUserServerClientType  = 0x99000003,
};

enum{
	kIOUserServerMethodRegisterClass = 0x0001000,
	kIOUserServerMethodStart         = 0x0001001,
	kIOUserServerMethodRegister      = 0x0001002,
};


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define OSObject_Instantiate_ID       0x0000000100000001ULL

enum {
	kOSObjectRPCRemote = 0x00000001,
	kOSObjectRPCKernel = 0x00000002,
};

struct OSObject_Instantiate_Msg_Content {
	IORPCMessage __hdr;
	OSObjectRef  __object;
};

#pragma pack(push, 4)
struct OSObject_Instantiate_Rpl_Content {
	IORPCMessage  __hdr;
	kern_return_t __result;
	uint32_t      __pad;
	uint64_t      flags;
	char          classname[128];
	uint64_t      methods[0];
};
#pragma pack(pop)

#pragma pack(4)
struct OSObject_Instantiate_Msg {
	IORPCMessageMach mach;
	mach_msg_port_descriptor_t __object__descriptor;
	OSObject_Instantiate_Msg_Content content;
};
struct OSObject_Instantiate_Rpl {
	IORPCMessageMach mach;
	OSObject_Instantiate_Rpl_Content content;
};
#pragma pack()

typedef uint64_t IOTrapMessageBuffer[256];

#endif /* DRIVERKIT_PRIVATE */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifdef XNU_KERNEL_PRIVATE

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <DriverKit/IOUserServer.h>
#include <libkern/c++/OSPtr.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSBoundedArray.h>
#include <libkern/c++/OSBoundedArrayRef.h>
#include <sys/reason.h>
class IOUserServer;
class OSUserMetaClass;
class OSObject;
class IODispatchQueue;
class IODispatchSource;
class IOInterruptDispatchSource;
class IOTimerDispatchSource;
class IOUserServerCheckInToken;
struct IOPStrings;

struct OSObjectUserVars {
	IOUserServer     * userServer;
	OSBoundedArrayRef<IODispatchQueue *> queueArray;
	OSUserMetaClass  * userMeta;
	OSArray          * openProviders;
	IOService        * controllingDriver;
	unsigned long      willPowerState;
	bool               willTerminate;
	bool               didTerminate;
	bool               serverDied;
	bool               started;
	bool               stopped;
	bool               userServerPM;
	bool               willPower;
	bool               powerState;
	bool               resetPowerOnWake;
	bool               deferredRegisterService;
	uint32_t           powerOverride;
	IOLock           * uvarsLock;
};

extern IOLock *        gIOUserServerLock;

typedef struct ipc_kmsg * ipc_kmsg_t;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

namespace IOServicePH
{
void serverAdd(IOUserServer * server);
void serverRemove(IOUserServer * server);
void serverAck(IOUserServer * server);
bool serverSlept(void);
void systemHalt(int howto);
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserServer : public IOUserClient2022
{
	OSDeclareDefaultStructorsWithDispatch(IOUserServer);

	IOLock       *        fLock;
	IOSimpleLock *        fInterruptLock;
	OSDictionary  *       fEntitlements;
	OSDictionary  *       fClasses;
	IODispatchQueue     * fRootQueue;
	OSArray             * fServices;

	uint8_t               fRootNotifier;
	uint8_t               fSystemPowerAck;
	uint8_t               fSystemOff;
	uint8_t               fPowerManagementFailed;
	IOUserServerCheckInToken * fCheckInToken;
	OSDextStatistics    * fStatistics;
	bool                  fPlatformDriver;
	OSString            * fTeamIdentifier;
	unsigned int          fCSValidationCategory;
public:
	kern_allocation_name_t fAllocationName;
	task_t                 fOwningTask;
	os_reason_t            fTaskCrashReason;

public:

	/*
	 * Launch a dext with the specified bundle ID, server name, and server tag. If reuseIfExists is true, this will attempt to find an existing IOUserServer instance or
	 * a pending dext launch with the same server name.
	 *
	 * Returns a IOUserServer instance if one was found, or a token to track the pending dext launch. If both are NULL, then launching the dext failed.
	 */
	static  IOUserServer * launchUserServer(OSString * bundleID, const OSSymbol * serverName, OSNumber * serverTag, bool reuseIfExists, IOUserServerCheckInToken ** token, OSData *serverDUI);
	static  IOUserClient * withTask(task_t owningTask);
	virtual IOReturn       clientClose(void) APPLE_KEXT_OVERRIDE;
	virtual bool           finalize(IOOptionBits options) APPLE_KEXT_OVERRIDE;
	virtual void           stop(IOService * provider) APPLE_KEXT_OVERRIDE;
	virtual void           free() APPLE_KEXT_OVERRIDE;

	virtual IOReturn       setProperties(OSObject * properties) APPLE_KEXT_OVERRIDE;
	virtual IOReturn       externalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque * args) APPLE_KEXT_OVERRIDE;
	static IOReturn        externalMethodStart(OSObject * target, void * reference, IOExternalMethodArguments * arguments);
	static IOReturn        externalMethodRegisterClass(OSObject * target, void * reference, IOExternalMethodArguments * arguments);

	virtual IOExternalTrap * getTargetAndTrapForIndex(IOService ** targetP, UInt32 index) APPLE_KEXT_OVERRIDE;

	IOReturn               serviceAttach(IOService * service, IOService * provider);
	IOReturn               serviceStop(IOService * service, IOService * provider);
	void                   serviceFree(IOService * service);
	IOReturn               serviceStarted(IOService * service, IOService * provider, bool result);
	static void            serviceWillTerminate(IOService * client, IOService * provider, IOOptionBits options);
	static void            serviceDidTerminate(IOService * client, IOService * provider, IOOptionBits options, bool * defer);
	static void            serviceDidStop(IOService * client, IOService * provider);
	IOReturn               serviceOpen(IOService * provider, IOService * client);
	IOReturn               serviceClose(IOService * provider, IOService * client);
	IOReturn               serviceJoinPMTree(IOService * service);
	IOReturn               serviceSetPowerState(IOService * controllingDriver, IOService * service, IOPMPowerFlags flags, IOPMPowerStateIndex powerState);
	IOReturn               serviceNewUserClient(IOService * service, task_t owningTask, void * securityID,
	    uint32_t type, OSDictionary * properties, IOUserClient ** handler);
	IOReturn               serviceNewUserClient(IOService * service, task_t owningTask, void * securityID,
	    uint32_t type, OSDictionary * properties, OSSharedPtr<IOUserClient>& handler);
	IOReturn               exit(const char * reason);
	IOReturn               kill(const char * reason);

	bool                   serviceMatchesCheckInToken(IOUserServerCheckInToken *token);
	bool                   checkEntitlements(IOService * provider, IOService * dext);
	static bool            checkEntitlements(OSDictionary * entitlements, LIBKERN_CONSUMED OSObject * prop,
	    IOService * provider, IOService * dext);

	void                   setTaskLoadTag(OSKext *kext);
	void                   setDriverKitUUID(OSKext *kext);
	void                   setDriverKitStatistics(OSKext *kext);
	void                   setCheckInToken(IOUserServerCheckInToken *token);
	void                   systemPower(bool powerOff);
	void                               systemHalt(int howto);
	static void            powerSourceChanged(bool acAttached);

	IOReturn                                setPowerState(unsigned long state, IOService * service) APPLE_KEXT_OVERRIDE;
	IOReturn                                powerStateWillChangeTo(IOPMPowerFlags flags, unsigned long state, IOService * service) APPLE_KEXT_OVERRIDE;
	IOReturn                                powerStateDidChangeTo(IOPMPowerFlags flags, unsigned long state, IOService * service) APPLE_KEXT_OVERRIDE;
	void                                    setPowerManagementFailed(bool failed);

	IOPStrings *           copyInStringArray(const char * string, uint32_t userSize);
	uint32_t               stringArrayIndex(IOPStrings * array, const char * look);
	IOReturn               registerClass(OSClassDescription * desc, uint32_t size, OSUserMetaClass ** cls);
	IOReturn               registerClass(OSClassDescription * desc, uint32_t size, OSSharedPtr<OSUserMetaClass>& cls);
	IOReturn               setRootQueue(IODispatchQueue * queue);

	OSObjectUserVars     * varsForObject(OSObject * obj);
	LIBKERN_RETURNS_NOT_RETAINED IODispatchQueue      * queueForObject(OSObject * obj, uint64_t msgid);

	static ipc_port_t      copySendRightForObject(OSObject * object, natural_t /* ipc_kobject_type_t */ type);
	static OSObject      * copyObjectForSendRight(ipc_port_t port, natural_t /* ipc_kobject_type_t */ type);

	IOReturn               copyOutObjects(IORPCMessageMach * mach, IORPCMessage * message,
	    size_t size, bool consume);
	IOReturn               copyInObjects(IORPCMessageMach * mach, IORPCMessage * message,
	    size_t size, bool copyObjects, bool consumePorts);

	IOReturn               consumeObjects(IORPCMessage * message, size_t messageSize);

	IOReturn               objectInstantiate(OSObject * obj, IORPC rpc, IORPCMessage * message);
	IOReturn               kernelDispatch(OSObject * obj, IORPC rpc);
	static OSObject      * target(OSAction * action, IORPCMessage * message);

	IOReturn               rpc(IORPC rpc);
	IOReturn               server(ipc_kmsg_t requestkmsg, ipc_kmsg_t * preply);
	kern_return_t          waitInterruptTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6);
	static bool            shouldLeakObjects();
	static void            beginLeakingObjects();
	bool                   isPlatformDriver();
	int                    getCSValidationCategory();
};

typedef void (*IOUserServerCheckInCancellationHandler)(class IOUserServerCheckInToken*, void*);

// OSObject wrapper around IOUserServerCheckInCancellationHandler
class _IOUserServerCheckInCancellationHandler : public OSObject {
	OSDeclareDefaultStructors(_IOUserServerCheckInCancellationHandler);
public:
	static _IOUserServerCheckInCancellationHandler *
	withHandler(IOUserServerCheckInCancellationHandler handler, void * args);

	void call(IOUserServerCheckInToken * token);
private:
	IOUserServerCheckInCancellationHandler fHandler;
	void                                 * fHandlerArgs;
};

class IOUserServerCheckInToken : public OSObject
{
	enum State {
		kIOUserServerCheckInPending,
		kIOUserServerCheckInCanceled,
		kIOUserServerCheckInComplete,
	};

	OSDeclareDefaultStructors(IOUserServerCheckInToken);
public:
	virtual void free() APPLE_KEXT_OVERRIDE;

	/*
	 * Cancel all pending dext launches.
	 */
	static void cancelAll();

	/*
	 * Set handler to be invoked when launch is cancelled. Returns an wrapper object for the handler to be released by the caller.
	 * The handler always runs under the lock for this IOUserServerCheckInToken.
	 * The returned object can be used with removeCancellationHandler().
	 */
	_IOUserServerCheckInCancellationHandler * setCancellationHandler(IOUserServerCheckInCancellationHandler handler, void *handlerArgs);

	/*
	 * Remove previously set cancellation handler.
	 */
	void removeCancellationHandler(_IOUserServerCheckInCancellationHandler * handler);

	/*
	 * Cancel the launch
	 */
	void cancel();

	/*
	 * Mark launch as completed.
	 */
	void complete();

	const OSSymbol * copyServerName() const;
	OSNumber * copyServerTag() const;

private:
	static IOUserServerCheckInToken * findExistingToken(const OSSymbol * serverName);
	bool init(const OSSymbol * userServerName, OSNumber * serverTag, OSKext *driverKext, OSData *serverDUI);
	bool dextTerminate(void);

	friend class IOUserServer;



private:
	IOUserServerCheckInToken::State          fState;
	size_t                                   fPendingCount;
	const OSSymbol                         * fServerName;
	const OSSymbol                         * fExecutableName;
	OSNumber                               * fServerTag;
	OSSet                                  * fHandlers;
	OSString                               * fKextBundleID;
	bool                                     fNeedDextDec;
};

extern "C" kern_return_t
IOUserServerUEXTTrap(OSObject * object, void * p1, void * p2, void * p3, void * p4, void * p5, void * p6);

extern "C" void
IOUserServerRecordExitReason(task_t task, os_reason_t reason);

#endif /* XNU_KERNEL_PRIVATE */
#endif /* _IOUSERSERVER_H */
