export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

LIBCXX_DATAFILES = \
	__xnu_libcxx_sentinel.h \
	errno.h  \
	stdio.h  \
	stdlib.h 

INSTALL_KF_LIBCXX_MI_LIST = ${LIBCXX_DATAFILES}

include $(MakeInc_rule)
include $(MakeInc_dir)
