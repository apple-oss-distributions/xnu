/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

#include <mach/port.h>
#include <mach/message.h>
#include <mach/kern_return.h>
#include <mach/host_priv.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/host.h>
#include <kern/ipc_kobject.h>

#include <ipc/ipc_port.h>

#include <UserNotification/UNDTypes.h>
#include <UserNotification/UNDRequest.h>
#include <UserNotification/UNDReplyServer.h>
#include <UserNotification/KUNCUserNotifications.h>

#ifdef KERNEL_CF
// external
#include <IOKit/IOCFSerialize.h>
#include <IOKit/IOCFUnserialize.h>
#endif

#if CONFIG_USER_NOTIFICATION
/*
 * DEFINES AND STRUCTURES
 */

struct UNDReply {
	decl_lck_mtx_data(, lock);                               /* UNDReply lock */
	int                             userLandNotificationKey;
	KUNCUserNotificationCallBack    callback;
	boolean_t                       inprogress;
	ipc_port_t                      self_port;      /* Our port */
};

static void
UNDReply_no_senders(ipc_port_t port, mach_port_mscount_t mscount);

IPC_KOBJECT_DEFINE(IKOT_UND_REPLY,
    .iko_op_stable     = true,
    .iko_op_no_senders = UNDReply_no_senders);

#define UNDReply_lock(reply)            lck_mtx_lock(&reply->lock)
#define UNDReply_unlock(reply)          lck_mtx_unlock(&reply->lock)

LCK_GRP_DECLARE(UNDLckGrp, "UND");

static UNDServerRef
UNDServer_reference(void)
{
	UNDServerRef UNDServer;
	kern_return_t kr;

	kr = host_get_user_notification_port(host_priv_self(), &UNDServer);
	assert(kr == KERN_SUCCESS);
	return UNDServer;
}

static void
UNDServer_deallocate(
	UNDServerRef    UNDServer)
{
	if (IP_VALID(UNDServer)) {
		ipc_port_release_send(UNDServer);
	}
}

/*
 * UND Mig Callbacks
 */

kern_return_t
UNDAlertCompletedWithResult_rpc(
	UNDReplyRef             reply,
	int                     result,
	xmlData_t               keyRef,         /* raw XML bytes */
#ifdef KERNEL_CF
	mach_msg_type_number_t  keyLen)
#else
	__unused mach_msg_type_number_t keyLen)
#endif
{
#ifdef KERNEL_CF
	CFStringRef             xmlError = NULL;
	CFDictionaryRef         dict = NULL;
#else
	const void *dict = (const void *)keyRef;
#endif

	if (reply == UND_REPLY_NULL || !reply->inprogress) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * JMM - No C vesion of the Unserialize code in-kernel
	 * and no C type for a CFDictionary either.  For now,
	 * just pass the raw keyRef through.
	 */
#ifdef KERNEL_CF
	if (keyRef && keyLen) {
		dict = IOCFUnserialize(keyRef, NULL, NULL, &xmlError);
	}

	if (xmlError) {
		CFShow(xmlError);
		CFRelease(xmlError);
	}
#endif /* KERNEL_CF */

	if (reply->callback) {
		(reply->callback)((int)(KUNCUserNotificationID)reply, result, dict);
	}

	UNDReply_lock(reply);
	reply->inprogress = FALSE;
	reply->userLandNotificationKey = -1;
	UNDReply_unlock(reply);

	return KERN_SUCCESS;
}

/*
 *	Routine: UNDNotificationCreated_rpc
 *
 *		Intermediate routine.  Allows the kernel mechanism
 *		to be informed that the notification request IS
 *		being processed by the user-level daemon, and how
 *		to identify that request.
 */
kern_return_t
UNDNotificationCreated_rpc(
	UNDReplyRef     reply,
	int             userLandNotificationKey)
{
	if (reply == UND_REPLY_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	UNDReply_lock(reply);
	if (reply->inprogress || reply->userLandNotificationKey != -1) {
		UNDReply_unlock(reply);
		return KERN_INVALID_ARGUMENT;
	}
	reply->userLandNotificationKey = userLandNotificationKey;
	UNDReply_unlock(reply);
	return KERN_SUCCESS;
}

/*
 * KUNC Functions
 */


KUNCUserNotificationID
KUNCGetNotificationID(void)
{
	UNDReplyRef reply;

	reply = kalloc_type(struct UNDReply, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	reply->self_port = ipc_kobject_alloc_port((ipc_kobject_t)reply,
	    IKOT_UND_REPLY, IPC_KOBJECT_ALLOC_NSREQUEST);
	lck_mtx_init(&reply->lock, &UNDLckGrp, LCK_ATTR_NULL);
	reply->userLandNotificationKey = -1;
	reply->inprogress = FALSE;

	return (KUNCUserNotificationID) reply;
}

static void
UNDReply_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	UNDReplyRef reply;

	reply = ipc_kobject_dealloc_port(port, mscount, IKOT_UND_REPLY);
	lck_mtx_destroy(&reply->lock, &UNDLckGrp);
	kfree_type(struct UNDReply, reply);
}

kern_return_t
KUNCExecute(char executionPath[1024], int uid, int gid)
{
	UNDServerRef UNDServer;

	UNDServer = UNDServer_reference();
	if (IP_VALID(UNDServer)) {
		kern_return_t kr;
		kr = UNDExecute_rpc(UNDServer, executionPath, uid, gid);
		UNDServer_deallocate(UNDServer);
		return kr;
	}
	return MACH_SEND_INVALID_DEST;
}

kern_return_t
KUNCUserNotificationDisplayNotice(
	int             noticeTimeout,
	unsigned        flags,
	char            *iconPath,
	char            *soundPath,
	char            *localizationPath,
	char            *alertHeader,
	char            *alertMessage,
	char            *defaultButtonTitle)
{
	UNDServerRef UNDServer;

	UNDServer = UNDServer_reference();
	if (IP_VALID(UNDServer)) {
		kern_return_t kr;
		kr = UNDDisplayNoticeSimple_rpc(UNDServer,
		    noticeTimeout,
		    flags,
		    iconPath,
		    soundPath,
		    localizationPath,
		    alertHeader,
		    alertMessage,
		    defaultButtonTitle);
		UNDServer_deallocate(UNDServer);
		return kr;
	}
	return MACH_SEND_INVALID_DEST;
}

kern_return_t
KUNCUserNotificationDisplayAlert(
	int             alertTimeout,
	unsigned        flags,
	char            *iconPath,
	char            *soundPath,
	char            *localizationPath,
	char            *alertHeader,
	char            *alertMessage,
	char            *defaultButtonTitle,
	char            *alternateButtonTitle,
	char            *otherButtonTitle,
	unsigned        *responseFlags)
{
	UNDServerRef    UNDServer;

	UNDServer = UNDServer_reference();
	if (IP_VALID(UNDServer)) {
		kern_return_t   kr;
		kr = UNDDisplayAlertSimple_rpc(UNDServer,
		    alertTimeout,
		    flags,
		    iconPath,
		    soundPath,
		    localizationPath,
		    alertHeader,
		    alertMessage,
		    defaultButtonTitle,
		    alternateButtonTitle,
		    otherButtonTitle,
		    responseFlags);
		UNDServer_deallocate(UNDServer);
		return kr;
	}
	return MACH_SEND_INVALID_DEST;
}

kern_return_t
KUNCUserNotificationDisplayFromBundle(
	KUNCUserNotificationID       id,
	char                         *bundlePath,
	char                         *fileName,
	char                         *fileExtension,
	char                         *messageKey,
	char                         *tokenString,
	KUNCUserNotificationCallBack callback,
	__unused int                    contextKey)
{
	UNDReplyRef reply = (UNDReplyRef)id;
	UNDServerRef UNDServer;
	ipc_port_t reply_port;

	if (reply == UND_REPLY_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	UNDReply_lock(reply);
	if (reply->inprogress == TRUE || reply->userLandNotificationKey != -1) {
		UNDReply_unlock(reply);
		return KERN_INVALID_ARGUMENT;
	}
	reply->inprogress = TRUE;
	reply->callback = callback;
	reply_port = ipc_port_make_send(reply->self_port);
	UNDReply_unlock(reply);

	UNDServer = UNDServer_reference();
	if (IP_VALID(UNDServer)) {
		kern_return_t kr;

		kr = UNDDisplayCustomFromBundle_rpc(UNDServer,
		    reply_port,
		    bundlePath,
		    fileName,
		    fileExtension,
		    messageKey,
		    tokenString);
		UNDServer_deallocate(UNDServer);
		return kr;
	}
	return MACH_SEND_INVALID_DEST;
}

/*
 *	Routine: convert_port_to_UNDReply
 *
 *		MIG helper routine to convert from a mach port to a
 *		UNDReply object.
 *
 *	Assumptions:
 *		Nothing locked.
 */
UNDReplyRef
convert_port_to_UNDReply(
	ipc_port_t port)
{
	UNDReplyRef reply = NULL;
	if (IP_VALID(port)) {
		reply = ipc_kobject_get_stable(port, IKOT_UND_REPLY);
	}

	return reply;
}
#endif

/*
 *      User interface for setting the host UserNotification Daemon port.
 */

kern_return_t
host_set_UNDServer(
	host_priv_t     host_priv,
	UNDServerRef    server)
{
#if CONFIG_USER_NOTIFICATION
	return host_set_user_notification_port(host_priv, server);
#else
#pragma unused(host_priv, server)
	return KERN_NOT_SUPPORTED;
#endif
}

/*
 *      User interface for retrieving the UserNotification Daemon port.
 */

kern_return_t
host_get_UNDServer(
	host_priv_t     host_priv,
	UNDServerRef    *serverp)
{
#if CONFIG_USER_NOTIFICATION
	return host_get_user_notification_port(host_priv, serverp);
#else
#pragma unused(host_priv, serverp)
	return KERN_NOT_SUPPORTED;
#endif
}
