export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MIG_DEFS =	\
	device.defs

MIG_HDRS = \

# Files that are public on macOS, but private on embedded
EMBEDDED_PRIVATE_DATAFILES = \
	device_types.defs \
	${MIG_DEFS}

ifeq ($(filter $(SUPPORTED_EMBEDDED_PLATFORMS) $(SUPPORTED_SIMULATOR_PLATFORMS),$(PLATFORM)),)
EXTRA_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
else
# Temporarily install some private defs in both usr/include and usr/local/include.
# They belong in usr/local/include, but installing them in both locations will allow
# clients that compile them by full path to switch without lock-step submissions.
EXTRA_DATAFILES = device.defs device_types.defs
EXTRA_PRIVATE_DATAFILES = $(EMBEDDED_PRIVATE_DATAFILES)
endif

DATAFILES = $(sort \
	device_types.h device_port.h \
	${EXTRA_DATAFILES})

MODULEMAPFILES = \
	device.modulemap

PRIVATE_DATAFILES = $(sort \
	device_types.h \
	${EXTRA_PRIVATE_DATAFILES})

# device_types.h has some userspace IOKit types that are used by
# IOTypes.h clients. The types are guarded by `IOKIT` because they
# conflict with internal xnu types. However, once device_types.h
# is part of the Darwin module, it gets processed before IOTypes.h
# defines IOKIT. Later when IOTypes.h includes the header, it's
# too late and the types don't get defined. Remove the IOKIT guard
# in userspace to fix that problem and always define the IOKit types.
KERNEL_ONLY_GUARDS_UNIFDEF = -DIOKIT

MIGINCLUDES = \

INSTALL_MI_LIST	= ${DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

INSTALL_MI_LCL_LIST = ${EXTRA_PRIVATE_DATAFILES}

INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

INSTALL_MI_DIR = device

EXPORT_MI_LIST	= ${DATAFILES} ${_MIG_HDRS_} ${MIGINCLUDES}

EXPORT_MI_DIR = device

#
# Build path
#
INCFLAGS_MAKEFILE= -I..

DEVICE_FILES    = device_server.h device_server.c

COMP_FILES	= ${DEVICE_FILES}

do_build_all:: $(COMP_FILES)

${DEVICE_FILES}: device.defs
	@$(LOG_MIG) "$@"
	$(_v)${MIG} ${MIGFLAGS} ${MIGKSFLAGS}	\
	-header /dev/null			\
	-user /dev/null				\
	-sheader device_server.h		\
	-server device_server.c			\
	$<

include $(MakeInc_rule)
include $(MakeInc_dir)
