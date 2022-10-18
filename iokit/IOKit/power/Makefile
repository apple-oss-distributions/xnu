export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MI_DIR = power
NOT_EXPORT_HEADERS =

ALL_HEADERS = $(notdir $(wildcard $(SOURCE)*.h))

INSTALL_IF_MI_LIST	=
INSTALL_IF_MI_LCL_LIST =
INSTALL_MI_DIR = $(MI_DIR)

EXPORT_MI_LIST	= $(filter-out $(NOT_EXPORT_HEADERS), $(ALL_HEADERS))
EXPORT_MI_DIR = IOKit/$(MI_DIR)

include $(MakeInc_rule)
include $(MakeInc_dir)
