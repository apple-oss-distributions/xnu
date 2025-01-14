export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	fasttrap_isa.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	endian.h param.h \
	profile.h signal.h limits.h _limits.h \
	types.h vmparam.h _types.h _param.h \
	_mcontext.h _endian.h \
	$(EXTRA_DATAFILES))

DRIVERKIT_DATAFILES = \
	limits.h _limits.h types.h _types.h endian.h _endian.h

PRIVATE_DATAFILES = $(sort \
	disklabel.h \
	$(EXTRA_PRIVATE_DATAFILES))

KERNELFILES = \
	endian.h param.h \
	profile.h signal.h limits.h _limits.h \
	types.h vmparam.h _types.h _param.h \
	_mcontext.h _endian.h

# These are covered by ../machine/machine.modulemap.
INSTALL_MD_LIST = ${DATAFILES}
INSTALL_DRIVERKIT_MD_LIST = ${DRIVERKIT_DATAFILES}
INSTALL_MD_LCL_LIST = ${EXTRA_PRIVATE_DATAFILES}
INSTALL_SF_MD_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MD_DIR = arm

EXPORT_MD_LIST = ${KERNELFILES}

EXPORT_MD_DIR = arm

include $(MakeInc_rule)
include $(MakeInc_dir)
