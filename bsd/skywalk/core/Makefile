export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \

EXPINC_SUBDIRS = \

# Installs header file for user level -
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
#	  $(DSTROOT)/usr/include/
DATAFILES= \

# Installs header file for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
KERNELFILES= \

# Installs header file for Apple internal use in user level -
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
PRIVATE_DATAFILES = \
	skywalk_common.h

# Installs header file for Apple internal use for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_KERNELFILES = \

INSTALL_MI_LIST	= ${DATAFILES}

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_SF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES})

# Installs header file for Apple internal use in user level -
#	  $(DSTROOT)/usr/local/include
# See also ../module.modulemap.
INSTALL_MI_LCL_LIST = $(sort ${PRIVATE_DATAFILES})

INSTALL_MI_DIR = skywalk

EXPORT_MI_LIST = $(sort ${INSTALL_MI_LIST} ${INSTALL_SF_MI_LCL_LIST})

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = $(sort ${KERNELFILES})

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST = $(sort ${KERNELFILES} ${PRIVATE_KERNELFILES})

include $(MakeInc_rule)
include $(MakeInc_dir)
