export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

TIGHTBEAMC_INCFLAGS = -I$(SRCROOT)/iokit/Exclaves

INCDIR = $(FRAMEDIR)/$(DKIT_INCDIR)
DRIVERKITINCDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_INCDIR)
LCLDIR = $(FRAMEDIR)/$(DKIT_PINCDIR)
DRIVERKITLCLDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_PINCDIR)

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =

PRIVATE_DEFS =

ifeq ($(XNU_CONFIG_TIGHTBEAM),1)
ALL_DEFS = $(notdir $(wildcard $(SOURCE)*.tightbeam))
endif
PUBLIC_DEFS = $(filter-out $(PRIVATE_DEFS), $(ALL_DEFS))
ALL_HDRS = $(notdir $(wildcard $(SOURCE)*.h))

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

INSTALL_MI_DIR = .

EXPORT_MI_DIR = Exclaves

GENERATED_HEADERS = $(patsubst %.tightbeam,%.tightbeam.h,$(ALL_DEFS))
PUBLIC_GENERATED_HEADERS = $(patsubst %.tightbeam,%.tightbeam.h,$(PUBLIC_DEFS))
PRIVATE_GENERATED_HEADERS = $(patsubst %.tightbeam,%.tightbeam.h,$(PRIVATE_DEFS))
OTHER_HEADERS = 

GENERATED_IMPL = $(patsubst %.tightbeam,%.tightbeam.c,$(ALL_DEFS))

INSTALL_MI_LIST = $(ALL_DEFS)
INSTALL_MI_LCL_LIST = $(ALL_DEFS)

INSTALL_KF_MI_GEN_LIST = $(PUBLIC_DEFS)

EXPORT_MI_LIST = $(ALL_HDRS)

COMP_FILES = ${GENERATED_HEADERS} $(GENERATED_IMPL)

$(GENERATED_HEADERS) : \
	%.tightbeam.h : %.tightbeam
	@$(LOG_TIGHTBEAMC) "$@"
	$(_v)$(TIGHTBEAMC) $(TIGHTBEAMC_INCFLAGS) --pass c --output-base $(patsubst %.tightbeam.h,%.tightbeam.c,$@) $<

$(GENERATED_IMPL) : $(GENERATED_HEADERS)

do_build_all:: $(COMP_FILES)

include $(MakeInc_rule)
include $(MakeInc_dir)
