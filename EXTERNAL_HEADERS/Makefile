export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =	\
	architecture	\
	mach-o			\
	sys

INSTINC_SUBDIRS_X86_64 =	\
	architecture

INSTINC_SUBDIRS_X86_64H =	\
	architecture

INSTINC_SUBDIRS_ARM64 =	\
	architecture

EXPORT_FILES = \
	Availability.h	\
	AvailabilityInternal.h	\
	AvailabilityMacros.h

KERNEL_FILES = \
	stdarg.h	\
	stdatomic.h	\
	stdbool.h	\
	stddef.h	\
	stdint.h	\
	ptrauth.h

LIBCXX_DATAFILES = \
	stddef.h \
	stdint.h

INSTALL_KF_LIBCXX_MI_LIST = ${LIBCXX_DATAFILES}

INSTALL_MI_LIST =

INSTALL_MI_DIR = .

INSTALL_KF_MI_LIST = ${KERNEL_FILES}

INSTALL_KF_MI_LCL_LIST = ${KERNEL_FILES}

EXPORT_MI_LIST = ${EXPORT_FILES} ${KERNEL_FILES}

EXPORT_MI_DIR = .

include $(MakeInc_rule)
include $(MakeInc_dir)
