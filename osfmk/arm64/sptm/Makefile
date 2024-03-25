export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# Ensure these files don't get auto-included into Kernel.framework.
INSTALL_KF_MD_LIST = $(EMPTY)
INSTALL_KF_MD_LCL_LIST = $(EMPTY)

# Headers exposed to the rest of the kernel.
EXPORT_MD_LIST = sptm.h

EXPORT_MD_DIR = arm64/sptm

include $(MakeInc_rule)
include $(MakeInc_dir)
