export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

INCDIR = $(FRAMEDIR)/$(DKIT_INCDIR)
DRIVERKITINCDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_INCDIR)
LCLDIR = $(FRAMEDIR)/$(DKIT_PINCDIR)
DRIVERKITLCLDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_PINCDIR)

include $(MakeInc_cmd)
include $(MakeInc_def)

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

MI_DIR = crypto
ALL_HEADERS = md5.h sha1.h aes.h sha2.h

INSTALL_MI_DIR = $(MI_DIR)

EXPORT_MI_DIR = DriverKit/$(MI_DIR)

INSTALL_MI_LCL_LIST = $(ALL_HEADERS)
INSTALL_DRIVERKIT_MI_LCL_LIST = $(ALL_HEADERS)
INSTALL_KF_MI_LCL_GEN_LIST = $(ALL_HEADERS)

do_build_all:: $(ALL_HEADERS)

include $(MakeInc_rule)
include $(MakeInc_dir)
