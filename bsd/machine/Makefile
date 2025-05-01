export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	fasttrap_isa.h _limits.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	byte_order.h  endian.h \
	limits.h param.h  profile.h \
	signal.h  types.h \
	vmparam.h _types.h _param.h \
	_mcontext.h _endian.h \
	$(EXTRA_DATAFILES))

DRIVERKIT_DATAFILES = \
	limits.h types.h _types.h endian.h _endian.h

PRIVATE_DATAFILES = $(sort \
	disklabel.h \
	$(EXTRA_PRIVATE_DATAFILES))

KERNELFILES = \
	disklabel.h \
	byte_order.h  endian.h \
	limits.h param.h   profile.h \
	signal.h types.h \
	vmparam.h _types.h _limits.h _param.h \
	_mcontext.h _endian.h

INSTALL_MI_LIST = ${DATAFILES}
INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}
INSTALL_MI_LCL_LIST = ${EXTRA_PRIVATE_DATAFILES}
INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)
