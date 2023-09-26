export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	nvram \
	platform \
	power \
	pwr_mgt \
	rtc \
	system_management \
	skywalk


EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

# By default, everything in xnu/iokit/IOKit gets installed into
# Kernel.framework/Headers/IOKit AND Kernel.framework/PrivateHeaders/IOKit.
# This is so the files with #ifdef ...PRIVATE portions can be processed.
# xnu/README documents the INSTALL* and EXPORT_MI_DIR lists.
ALL_HEADERS = $(notdir $(wildcard $(SOURCE)*.h))

# Do not install these headers (anywhere).
NOT_EXPORT_HEADERS = IOInterruptAccountingPrivate.h

# Install these only in Kernel.framework's PrivateHeaders (not Headers).
NOT_KF_MI_HEADERS  = $(NOT_EXPORT_HEADERS)			\
		     IOKitKeysPrivate.h IOCPU.h			\
		     IOHibernatePrivate.h IOPolledInterface.h	\
		     IOCommandQueue.h IOLocksPrivate.h		\
		     IOSyncer.h AppleKeyStoreInterface.h	\
		     IOStatistics.h IOStatisticsPrivate.h	\
		     IOKernelReporters.h			\
		     IOInterruptAccounting.h			\
		     IOPlatformIO.h				\
		     IOPMGR.h IOPlatformActions.h 	\
		     IOExtensiblePaniclog.h


# These should be additionally installed in IOKit.framework's public Headers
INSTALL_IF_MI_LIST	= IOBSD.h IOKitKeys.h IOKitServer.h IOReturn.h	    \
		  IOSharedLock.h IOTypes.h IOMapTypes.h OSMessageNotification.h  \
		  IODataQueueShared.h IOMessage.h IORPC.h IOUserServer.h

# These should be additionally installed in IOKit.framework's PrivateHeaders
INSTALL_IF_MI_LCL_LIST = $(INSTALL_IF_MI_LIST)
INSTALL_IF_MI_LCL_LIST += \
		      IOKitKeysPrivate.h IOHibernatePrivate.h   \
		      IOLocksPrivate.h IOStatistics.h 		\
		      AppleKeyStoreInterface.h  		\
		      IOReportTypes.h IOKernelReportStructs.h   \
		      IOReportMacros.h IOInterruptAccounting.h

INSTALL_MI_DIR = .

EXPORT_MI_LIST	= $(filter-out $(NOT_EXPORT_HEADERS), $(ALL_HEADERS))

EXPORT_MI_DIR = IOKit

INSTALL_KF_MI_LIST = $(filter-out $(NOT_KF_MI_HEADERS), $(ALL_HEADERS))

include $(MakeInc_rule)
include $(MakeInc_dir)
