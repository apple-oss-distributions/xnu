export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir
export MakeInc_san=${SRCROOT}/makedefs/MakeInc.san

include $(MakeInc_cmd)
include $(MakeInc_def)
include $(MakeInc_san)

DATAFILES = \

PRIVATE_DATAFILES = \

KERNELFILES = \

PRIVATE_KERNELFILES = \

# Available only in xnu proper
PRIVATE_XNUFILES = \
	kcov.h \
	kcov_data.h \
	kcov_ksancov.h \
	kcov_ksancov_data.h \
	kcov_stksz.h \
	kcov_stksz_data.h

INSTALL_MI_LIST = ${DATAFILES}
INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}
INSTALL_KF_MI_LIST = ${KERNELFILES}
INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = ${PRIVATE_XNUFILES} ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_MI_DIR = san
EXPORT_MI_DIR = san

# Generate blacklist
.DELETE_ON_ERROR:
$(OBJROOT)/san/kcov-blacklist-%: $(SOURCE)/kcov-blacklist $(SOURCE)/kcov-blacklist-%
	@$(LOG_GENERATE) "$(notdir $@)"
	$(_v)sed -e 's,^src:\./,src:'"$(SRCROOT)/," $^ > $@
	$(_v)$(SRCROOT)/san/tools/validate_blacklist.sh "$@"

do_build_setup:: $(OBJROOT)/san/kcov-blacklist-x86_64 $(OBJROOT)/san/kcov-blacklist-arm64

#
# Kcov System.kext plugin
#

ifneq ($(RC_ProjectName),xnu_libraries)

#
# Primary build will always install kext without exported runtime.
#
# Note: Skipped when kasan only install is requested.
#

ifneq ($(INSTALL_KASAN_ONLY),1)

KEXT := Kcov

$(eval $(call san_symbolset_template,$(KEXT),Kcov_disabled))
$(eval $(call san_kext_dstroot_rule_template,Kcov.kext,$(KEXT)))
$(eval $(call san_kext_symroot_rule_template,Kcov.kext,$(KEXT),$(BUILD_CONFIGS)))

do_config_all:: $(SYMBOL_SET_BUILD_$(KEXT))
do_config_install:: $(SYMROOT_KEXT_$(KEXT)) $(DSTROOT_KEXT_$(KEXT))

endif

#
# Non-primary build variant install target.
#
# Include variant only when sanitizer runtime is enabled.
#

ifneq ($(filter $(CURRENT_KERNEL_CONFIG), $(KCOV_RUNTIME)),)

# all build configs for the current variant
CURRENT_VARIANT_BUILD_CONFIGS := $(strip $(call function_match_build_config_for_kernel_config, \
		$(BUILD_CONFIGS), $(CURRENT_KERNEL_CONFIG)))

KEXT_VARIANT := Kcov_$(CURRENT_KERNEL_CONFIG_LC)

$(eval $(call san_symbolset_template,$(KEXT_VARIANT),Kcov_enabled))
$(eval $(call san_kext_dstroot_rule_template,Kcov.kext,$(KEXT_VARIANT)))
$(eval $(call san_kext_symroot_rule_template,Kcov.kext,$(KEXT_VARIANT),$(CURRENT_VARIANT_BUILD_CONFIGS)))

do_config_all:: $(SYMBOL_SET_BUILD_$(KEXT_VARIANT))
do_config_install_variant:: $(SYMROOT_KEXT_$(KEXT_VARIANT)) $(DSTROOT_KEXT_$(KEXT_VARIANT))

endif

else
# We are building XNU as a static library - no need for the symbol kexts
endif

include $(MakeInc_rule)
include $(MakeInc_dir)
