export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

IIG_INCFLAGS = -I$(SRCROOT)/iokit -I$(SRCROOT)/osfmk -I$(SRCROOT)/bsd -I$(OBJROOT)/bsd $(INCFLAGS_EXTERN)
OTHER_IIG_CFLAGS = $(IIG_INCFLAGS) -isysroot $(SDKROOT) -x c++ -std=gnu++2b -D__IIG=1 -DDRIVERKIT_PRIVATE=1 -DPRIVATE_WIFI_ONLY=1 $(DEPLOYMENT_TARGET_DEFINES)

INCDIR = $(FRAMEDIR)/$(DKIT_INCDIR)
DRIVERKITINCDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_INCDIR)
LCLDIR = $(FRAMEDIR)/$(DKIT_PINCDIR)
DRIVERKITLCLDIR = $(DRIVERKITFRAMEDIR)/$(DRIVERKIT_DKIT_PINCDIR)

include $(MakeInc_cmd)
include $(MakeInc_def)

ALL_DEFS = $(notdir $(wildcard $(SOURCE)*.iig))

GENERATED_HEADERS = $(patsubst %.iig,%.h,$(ALL_DEFS))

GENERATED_IMPL = $(patsubst %.iig,%.iig.cpp,$(ALL_DEFS))

COMP_FILES = ${GENERATED_HEADERS} $(GENERATED_IMPL)

INSTALL_MI_DIR = .

INSTALL_MI_LIST = $(ALL_DEFS)
INSTALL_MI_LCL_LIST = $(ALL_DEFS)

INSTALL_MI_GEN_LIST = $(GENERATED_HEADERS)
INSTALL_MI_LCL_GEN_LIST = $(GENERATED_HEADERS)

$(GENERATED_HEADERS) : \
	%.h : %.iig
	@$(LOG_IIG) "$@"
	$(_v)$(IIG) --def $< --header $@ --impl $(patsubst %.h,%.iig.cpp.tmp,$@) ${OTHER_IIG_FLAGS} -- ${OTHER_IIG_CFLAGS} $(_vstdout)
	$(_v)$(ECHO) '#if DEBUG || DEVELOPMENT' > $(patsubst %.h,%.iig.cpp,$@)
	$(_v)$(CAT) $(patsubst %.h,%.iig.cpp.tmp,$@) >> $(patsubst %.h,%.iig.cpp,$@)
	$(_v)$(ECHO) '#endif' >> $(patsubst %.h,%.iig.cpp,$@)

$(GENERATED_IMPL) : $(GENERATED_HEADERS)

do_build_all:: $(COMP_FILES)

include $(MakeInc_rule)
include $(MakeInc_dir)