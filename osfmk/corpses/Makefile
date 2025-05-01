export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	task_corpse.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	$(EXTRA_DATAFILES))

PRIVATE_DATAFILES = $(sort \
	$(EXTRA_PRIVATE_DATAFILES))

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = corpses

EXPORT_MI_LIST	= ${DATAFILES} ${PRIVATE_DATAFILES}

EXPORT_MI_DIR = corpses

include $(MakeInc_rule)
include $(MakeInc_dir)
