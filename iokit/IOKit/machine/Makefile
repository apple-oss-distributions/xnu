export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

MI_DIR = machine
EXCLUDE_HEADERS =

ALL_HEADERS = $(notdir $(wildcard $(SOURCE)*.h))
HEADER_LIST = $(filter-out $(EXCLUDE_HEADERS), $(ALL_HEADERS))

INSTALL_IF_MI_LIST	= ${HEADER_LIST}
INSTALL_IF_MI_LCL_LIST = ${HEADER_LIST}
INSTALL_MI_DIR = $(MI_DIR)

EXPORT_MI_LIST	= ${HEADER_LIST}
EXPORT_MI_DIR = IOKit/$(MI_DIR)

include $(MakeInc_rule)
include $(MakeInc_dir)
