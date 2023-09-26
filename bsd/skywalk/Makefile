export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = \
	core channel mem nexus packet namespace

EXPINC_SUBDIRS = \
	core channel mem nexus packet namespace

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
	os_skywalk.h os_skywalk_private.h os_stats_private.h	\
	os_sysctls_private.h

# Installs header file for Apple internal use for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_KERNELFILES = \
	os_skywalk.h

# Makes module map file available to Apple internal in user level -
#	  $(DSTROOT)/usr/local/include
PRIVATE_MODULEMAPFILES = \
	module.modulemap

INSTALL_MI_LIST	= ${DATAFILES}

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_SF_MI_LCL_LIST = $(sort ${DATAFILES} ${PRIVATE_DATAFILES})

# Installs header file for Apple internal use in user level -
#	  $(DSTROOT)/usr/local/include
# See also module.modulemap.
INSTALL_MI_LCL_LIST = $(sort ${PRIVATE_DATAFILES})

INSTALL_MODULEMAP_MI_LCL_LIST = ${PRIVATE_MODULEMAPFILES}

INSTALL_MI_DIR = skywalk

INSTALL_MODULEMAP_MI_DIR = skywalk

EXPORT_MI_LIST = $(sort ${INSTALL_MI_LIST} ${INSTALL_SF_MI_LCL_LIST})

EXPORT_MI_DIR = ${INSTALL_MI_DIR}

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = $(sort ${KERNELFILES})

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST = $(sort ${KERNELFILES} ${PRIVATE_KERNELFILES})

include $(MakeInc_rule)
include $(MakeInc_dir)
