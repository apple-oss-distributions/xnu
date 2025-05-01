export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_DEFS = mach_debug_types.defs

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	${MIG_DEFS}

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	mach_debug.h \
	hash_info.h ipc_info.h vm_info.h zone_info.h \
	page_info.h mach_debug_types.h lockgroup_info.h \
	${EXTRA_DATAFILES})

MODULEMAPFILES = \
	mach_debug.modulemap

PRIVATE_DATAFILES = $(sort \
	${EXTRA_PRIVATE_DATAFILES})

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

INSTALL_MI_LCL_LIST = $(sort \
	${EXTRA_PRIVATE_DATAFILES})

INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_KF_MI_LIST = ${DATAFILES} ${EXTRA_PRIVATE_DATAFILES}

INSTALL_KF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = mach_debug

EXPORT_MI_LIST	= ${DATAFILES}

EXPORT_MI_DIR = mach_debug

include $(MakeInc_rule)
include $(MakeInc_dir)
