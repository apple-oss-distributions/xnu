export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

KERNELFILES = \
	atomic.h \
	alloc_util.h \
	base.h \
	cpp_util.h \
	log.h \
	object.h \
	overflow.h \
	trace.h

PRIVATE_KERNELFILES = \
	atomic_private.h	\
	atomic_private_arch.h	\
	atomic_private_impl.h	\
	base_private.h \
	hash.h \
	ptrtools.h \
	reason_private.h \
	refcnt.h \
	refcnt_internal.h \
	cxx_safe_buffers.h \
	system_event_log.h

DATAFILES = \
	atomic.h \
	base.h \
	overflow.h

DRIVERKIT_DATAFILES = \
	atomic.h \
	base.h \
	overflow.h

EXCLAVEKIT_DATAFILES = \
	base.h \
	base_private.h \
	cxx_safe_buffers.h

EXCLAVECORE_DATAFILES = \
	base.h \
	base_private.h  \
	cxx_safe_buffers.h

PRIVATE_DATAFILES = \
	atomic_private.h	\
	atomic_private_arch.h	\
	atomic_private_impl.h	\
	base_private.h \
	reason_private.h \
	cxx_safe_buffers.h \
	system_event_log.h

INSTALL_MI_LIST = ${DATAFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

INSTALL_EXCLAVEKIT_MI_LIST = ${EXCLAVEKIT_DATAFILES}

INSTALL_EXCLAVECORE_MI_LIST = ${EXCLAVECORE_DATAFILES}

INSTALL_MI_DIR = os

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = \
	${KERNELFILES} ${PRIVATE_KERNELFILES} log_private.h

EXPORT_MI_DIR = os

include $(MakeInc_rule)
include $(MakeInc_dir)
