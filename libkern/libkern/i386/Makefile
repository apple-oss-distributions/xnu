export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
          OSByteOrder.h \
          _OSByteOrder.h

DRIVERKIT_DATAFILES = \
          OSByteOrder.h \
          _OSByteOrder.h

INSTALL_MD_LIST	= ${DATAFILES}

INSTALL_SF_MD_LCL_LIST = ${DATAFILES}

INSTALL_DRIVERKIT_MD_LIST = ${DRIVERKIT_DATAFILES}

DRIVERKITINCDIR = $(DRIVERKITSDKHEADERSROOT)/usr/local/include

INSTALL_MD_DIR = libkern/i386

EXPORT_MD_LIST	= ${DATAFILES}

EXPORT_MD_DIR = libkern/i386

include $(MakeInc_rule)
include $(MakeInc_dir)
