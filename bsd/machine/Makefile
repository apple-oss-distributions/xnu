export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	_limits.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	byte_order.h  endian.h fasttrap_isa.h \
	limits.h param.h  profile.h \
	signal.h  types.h \
	vmparam.h _types.h _param.h \
	_mcontext.h \
	$(EXTRA_DATAFILES))

# machine.modulemap additionally includes the headers from ../{i386,arm} and
# ../../osfmk/{i386,arm}.
MODULEMAPFILES = \
	machine.modulemap

DRIVERKIT_DATAFILES = \
	limits.h types.h _types.h endian.h

PRIVATE_DATAFILES = $(sort \
	disklabel.h \
	$(EXTRA_PRIVATE_DATAFILES))

# machine_private.modulemap additionally includes the headers from ../../osfmk/{machine,i386,arm}.
PRIVATE_MODULEMAPFILES = \
	machine_private.modulemap

KERNELFILES = \
	disklabel.h \
	byte_order.h  endian.h \
	limits.h param.h   profile.h \
	signal.h types.h \
	vmparam.h _types.h _limits.h _param.h \
	_mcontext.h

INSTALL_MI_LIST = ${DATAFILES}
INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}
INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}
INSTALL_MI_LCL_LIST = ${EXTRA_PRIVATE_DATAFILES}
INSTALL_MODULEMAP_MI_LCL_LIST = ${PRIVATE_MODULEMAPFILES}
INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = machine

EXPORT_MI_LIST = ${KERNELFILES}

EXPORT_MI_DIR = machine

include $(MakeInc_rule)
include $(MakeInc_dir)
