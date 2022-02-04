export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

VPATH := $(VPATH):$(SOURCE)/../../arm64

DATAFILES =

INSTALL_MD_LIST = ${DATAFILES}

INSTALL_SF_MD_LCL_LIST = ${DATAFILES}

# These are covered by ../machine/mach_machine.modulemap.
INSTALL_MD_GEN_LIST = \
	asm.h

INSTALL_SF_MD_LCL_GEN_LIST = \
	asm.h

INSTALL_MD_DIR = mach/arm64

EXPORT_MD_LIST = ${DATAFILES}

EXPORT_MD_GEN_LIST = \
	asm.h

EXPORT_MD_DIR = mach/arm64

include $(MakeInc_rule)
include $(MakeInc_dir)
