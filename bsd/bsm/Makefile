export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	audit_domain.h audit_errno.h audit_fcntl.h audit_internal.h \
	audit_kevents.h audit_record.h audit_socket_type.h

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

# These are covered by CoreOSModuleMaps because they're
# mixed in with headers from other projects in bsm/.
DATAFILES = $(sort \
	audit.h \
	$(EXTRA_DATAFILES))

# These are covered by CoreOSModuleMaps because they're
# mixed in with headers from other projects in bsm/.
PRIVATE_DATAFILES = $(sort \
	$(EXTRA_PRIVATE_DATAFILES))

KERNFILES = \
	audit.h

INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

INSTALL_MI_DIR = bsm

EXPORT_MI_LIST	= ${KERNFILES}

EXPORT_MI_DIR = bsm

include $(MakeInc_rule)
include $(MakeInc_dir)
