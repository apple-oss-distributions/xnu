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
	memintrinsics.h

# Available only in xnu proper
PRIVATE_XNUFILES = \
	kasan.h \
	kasan-classic.h \
	kasan-tbi.h \
	ubsan_minimal.h

INSTALL_MI_LIST = ${DATAFILES}
INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}
INSTALL_KF_MI_LIST = ${KERNELFILES}
INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_LIST = ${PRIVATE_XNUFILES} ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_MI_DIR = san
EXPORT_MI_DIR = san

.DELETE_ON_ERROR:
$(OBJROOT)/san/kasan-blacklist-%: $(SOURCE)/kasan-blacklist $(SOURCE)/ubsan-blacklist $(SOURCE)/kasan-blacklist-%
	@$(LOG_GENERATE) "$(notdir $@)"
	$(_v)sed -e 's,^src:\./,src:'"$(SRCROOT)/," $^ > $@
	$(_v)$(SRCROOT)/san/tools/validate_blacklist.sh "$@"

do_build_setup:: $(OBJROOT)/san/kasan-blacklist-x86_64 $(OBJROOT)/san/kasan-blacklist-arm64

#
# Kasan System.kext plugin
#

ifneq ($(RC_ProjectName),xnu_libraries)

#
# Primary build will always install kext without exported runtime.
#
# Note: Skipped when kasan only install is requested.
#

ifneq ($(INSTALL_KASAN_ONLY),1)

KEXT := Kasan

$(eval $(call san_symbolset_template,$(KEXT),Kasan_disabled))
$(eval $(call san_kext_dstroot_rule_template,Kasan.kext,$(KEXT)))
$(eval $(call san_kext_symroot_rule_template,Kasan.kext,$(KEXT),$(BUILD_CONFIGS)))

do_config_all:: $(SYMBOL_SET_BUILD_$(KEXT))
do_config_install:: $(SYMROOT_KEXT_$(KEXT)) $(DSTROOT_KEXT_$(KEXT))

endif

#
# Non-primary build variant install target.
#

ifeq ($(KASAN),1)

# KASAN symbols are per-architecture, since on arm64/arm64e we use KASAN_TBI by default
# and on x86/arm KASAN_CLASSIC
ifeq ($(CURRENT_ARCH_CONFIG_LC),x86_64h)
KASAN_ARCH_SUFFIX := x86_64
else
KASAN_ARCH_SUFFIX := $(CURRENT_ARCH_CONFIG_LC)
endif

# all build configs for the current variant
CURRENT_VARIANT_BUILD_CONFIGS := $(strip $(call function_match_build_config_for_kernel_config, \
		$(BUILD_CONFIGS), $(CURRENT_KERNEL_CONFIG)))

KEXT_VARIANT := Kasan_$(CURRENT_KERNEL_CONFIG_LC)

$(eval $(call san_symbolset_template,$(KEXT_VARIANT),Kasan_enabled.$(KASAN_ARCH_SUFFIX)))
$(eval $(call san_kext_dstroot_rule_template,Kasan.kext,$(KEXT_VARIANT)))
$(eval $(call san_kext_symroot_rule_template,Kasan.kext,$(KEXT_VARIANT),$(CURRENT_VARIANT_BUILD_CONFIGS)))

do_config_all:: $(SYMBOL_SET_BUILD_$(KEXT_VARIANT))
do_config_install_variant:: $(SYMROOT_KEXT_$(KEXT_VARIANT)) $(DSTROOT_KEXT_$(KEXT_VARIANT))

endif

else
# We are building XNU as a static library - no need for the symbol kexts
endif

# Install helper scripts

ifeq ($(KASAN),1)
KASAN_HELPER_SCRIPTS += $(DSTROOT)/$(DEVELOPER_EXTRAS_DIR)/kasan_install
endif

$(KASAN_HELPER_SCRIPTS): $(DSTROOT)/$(DEVELOPER_EXTRAS_DIR)/% : $(SRCROOT)/san/tools/%
	$(_v)$(MKDIR) $(dir $@)
	@$(LOG_INSTALL) "$(@F)"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

do_config_install:: $(KASAN_HELPER_SCRIPTS)

include $(MakeInc_rule)
include $(MakeInc_dir)
