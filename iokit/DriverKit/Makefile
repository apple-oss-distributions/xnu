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

INSTINC_SUBDIRS = crypto

PRIVATE_DEFS = IOEventLink.iig IOWorkGroup.iig IOExtensiblePaniclog.iig

ALL_DEFS = $(notdir $(wildcard $(SOURCE)*.iig))
PUBLIC_DEFS = $(filter-out $(PRIVATE_DEFS), $(ALL_DEFS))
ALL_HDRS = $(notdir $(wildcard $(SOURCE)*.h))

EXPINC_SUBDIRS = ${INSTINC_SUBDIRS}

INSTALL_MI_DIR = .

EXPORT_MI_DIR = DriverKit

GENERATED_HEADERS = $(patsubst %.iig,%.h,$(ALL_DEFS))
PUBLIC_GENERATED_HEADERS = $(patsubst %.iig,%.h,$(PUBLIC_DEFS))
PRIVATE_GENERATED_HEADERS = $(patsubst %.iig,%.h,$(PRIVATE_DEFS))

GENERATED_IMPL = $(patsubst %.iig,%.iig.cpp,$(ALL_DEFS))

INSTALL_MI_LIST = $(ALL_DEFS)
INSTALL_MI_LCL_LIST = $(ALL_DEFS)
INSTALL_DRIVERKIT_MI_LIST = $(PUBLIC_DEFS)
INSTALL_DRIVERKIT_MI_LCL_LIST = $(PRIVATE_DEFS)

OTHER_HEADERS = IOTypes.h IOReturn.h IORPC.h IOKitKeys.h \
				IOKernelReportStructs.h IOReportTypes.h \
				queue_implementation.h macro_help.h \
				bounded_ptr.h bounded_array.h bounded_array_ref.h bounded_ptr_fwd.h \
				OSBoundedArray.h OSBoundedArrayRef.h OSBoundedPtr.h OSBoundedPtrFwd.h \
				safe_allocation.h

EXPORT_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)
INSTALL_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)
INSTALL_MI_LCL_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)
INSTALL_DRIVERKIT_MI_GEN_LIST = $(PUBLIC_GENERATED_HEADERS) $(OTHER_HEADERS)
INSTALL_DRIVERKIT_MI_LCL_GEN_LIST = $(PRIVATE_GENERATED_HEADERS)
INSTALL_KF_MI_GEN_LIST = $(GENERATED_HEADERS)  $(OTHER_HEADERS)

COMP_FILES = ${GENERATED_HEADERS} $(GENERATED_IMPL)

ifeq ($(filter 1,$(EXCLAVEKIT) $(EXCLAVECORE)),)
$(GENERATED_HEADERS) : \
	%.h : %.iig
	@$(LOG_IIG) "$@"
	$(_v)$(IIG) --def $< --header $@ --impl $(patsubst %.h,%.iig.cpp,$@) --framework-name DriverKit ${OTHER_IIG_FLAGS} -- ${OTHER_IIG_CFLAGS} $(_vstdout)

$(GENERATED_IMPL) : $(GENERATED_HEADERS)

do_build_all:: $(COMP_FILES)
endif

include $(MakeInc_rule)
include $(MakeInc_dir)
