export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	atm_types.h \
	${MIG_TYPES} \
	${MIG_DEFS}

INSTALL_MI_LIST	= \
	${DATAFILES}

INSTALL_SF_MI_LCL_LIST = \
	${DATAFILES}

INSTALL_KF_MI_LIST = \
	${DATAFILES}

INSTALL_KF_MI_LCL_LIST = \
	${DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = atm

EXPORT_MI_LIST	= \
	${DATAFILES} atm_internal.h

EXPORT_MI_DIR = atm

include $(MakeInc_rule)
include $(MakeInc_dir)
