export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

# config is not a COMPONENT but we still want to build most files in a TARGET subdir
override TARGET := $(OBJPATH)/config

MD_SUPPORTED_KPI_FILENAME := SupportedKPIs-${CURRENT_ARCH_CONFIG_LC}.txt
MI_SUPPORTED_KPI_FILENAME := SupportedKPIs-all-archs.txt

INSTALL_KEXT_DIR = $(DSTROOT)$(INSTALL_EXTENSIONS_DIR)

KEXT_PLIST_LIST := \
	System.kext/Info.plist \
	System.kext/PlugIns/Kasan.kext/Info.plist \
	System.kext/PlugIns/Kcov.kext/Info.plist \
	System.kext/PlugIns/AppleNMI.kext/Info.plist \
	System.kext/PlugIns/ApplePlatformFamily.kext/Info.plist \
	System.kext/PlugIns/IONVRAMFamily.kext/Info.plist \
	System.kext/PlugIns/IOSystemManagement.kext/Info.plist

SYMBOL_COMPONENT_LIST :=	\
        BSDKernel	\
        IOKit		\
        Libkern		\
        Mach		\
        MACFramework	\
        Unsupported	\
        Private

SYMBOL_SET_PLIST_COMPONENT_LIST := $(SYMBOL_COMPONENT_LIST) Kasan Kcov

KEXT_PLIST_LIST += $(foreach symbolset,$(SYMBOL_COMPONENT_LIST),System.kext/PlugIns/$(symbolset).kext/Info.plist)

# In general you want it to be possible to have a CPU sub-type's symbol exports
# alias to the parent type's exports. This is a special-case way to handle it
# for now:
ifeq ($(CURRENT_ARCH_CONFIG_LC),x86_64h)
EXPORT_SOURCE_ARCH_CONFIG_LC := x86_64
else
EXPORT_SOURCE_ARCH_CONFIG_LC := $(CURRENT_ARCH_CONFIG_LC)
endif

EXPORTS_FILES := $(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(symbolset).exports \
	$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports \
	$(notdir $(wildcard $(SOURCE)/$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).$(PLATFORM).exports))) \
	Unused.exports
EXPORTS_FILES += $(TIGHTBEAM_EXPORTS)
Private_OTHER_EXPORTS += $(TIGHTBEAM_EXPORTS)


Kasan_EXPORTS := $(SRCROOT)/config/Kasan_disabled.exports
Kcov_EXPORTS := $(SRCROOT)/config/Kcov_disabled.exports

ifneq ($(filter $(CURRENT_KERNEL_CONFIG),$(KCOV_RUNTIME)),)
Kcov_EXPORTS := $(SRCROOT)/config/Kcov_enabled.exports
endif

ifeq ($(KASAN),1)
ifeq ($(CURRENT_ARCH_CONFIG_LC),x86_64h)
KASAN_ARCH_SUFFIX := x86_64
else
KASAN_ARCH_SUFFIX := $(CURRENT_ARCH_CONFIG_LC)
endif
Kasan_EXPORTS := $(SRCROOT)/config/Kasan_enabled.$(KASAN_ARCH_SUFFIX).exports
endif

define symbol_set_template
$(1)_EXPORTS := $$(addprefix $$(SOURCE)/,$$(filter $(1)%,$$(EXPORTS_FILES)))
ifneq "$$($(1)_OTHER_EXPORTS)" ""
$(1)_EXPORTS += $$($(1)_OTHER_EXPORTS)
endif
$$(TARGET)/$(1).symbolset: MY_EXPORTS_ARGS := $$(foreach file,$$($(1)_EXPORTS),-export $$(file))
$$(TARGET)/$(1).symbolset: $$($(1)_EXPORTS) $$(TARGET)/allsymbols $$(KEXT_CREATE_SYMBOL_SET)
	@$$(LOG_SYMBOLSET) "$(1)$$(Color0) ($$(ColorLF)$$(CURRENT_ARCH_CONFIG_LC)$$(Color0))"
	$$(_v)$$(KEXT_CREATE_SYMBOL_SET)			\
		$$(ARCH_FLAGS_$$(CURRENT_ARCH_CONFIG))	\
		-import $$(TARGET)/allsymbols		\
		$$(MY_EXPORTS_ARGS)			\
		-output $$@ $$(_vstdout)

SYMBOL_SET_BUILD += $$(TARGET)/$(1).symbolset
endef

# Each parallel invocation of this target must use a distinct location, as it is
# not safe to call multiple NEWVERS on the same file concurrently (rdar://66173684)
define kext_plist_template
$$(TARGET)/$(1): $$(SOURCE)/$(1) $$(NEWVERS) $$(XNU_VERSION)
	@$$(LOG_GENERATE) "$(1)"
	$$(_v)$$(MKDIR) $$(@D)
	$$(_v)$$(CP) $$< $$@
	$$(_v)$$(NEWVERS) $$@ > /dev/null

KEXT_PLIST_BUILD += $$(TARGET)/$(1)
SYMROOT_INSTALL_KEXT_PLISTS += $$(SYMROOT)/$(1)
DSTROOT_INSTALL_KEXT_PLISTS += $$(INSTALL_KEXT_DIR)/$(1)
endef

define symbol_set_plist_template
$(1)_KEXT_PLIST := $$(filter %/$(1).kext/Info.plist,$$(KEXT_PLIST_LIST))
$$(TARGET)/$(1).symbolset.plist: $$(TARGET)/$$($(1)_KEXT_PLIST) $$($(1)_EXPORTS)
	@$$(LOG_SYMBOLSETPLIST) "$(1)$$(Color0) ($$(ColorLF)$$(CURRENT_ARCH_CONFIG_LC)$$(Color0))"
	$$(_v)$$(SOURCE)/generate_symbolset_plist.sh $$@ $$+ $$(_vstdout)
	$$(_v)$$(PLUTIL) -lint -s $$@

SYMBOL_SET_PLIST_BUILD += $$(TARGET)/$(1).symbolset.plist
endef

$(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(eval $(call symbol_set_template,$(symbolset))))
$(foreach plist,$(KEXT_PLIST_LIST),$(eval $(call kext_plist_template,$(plist))))
$(foreach symbolset,$(SYMBOL_SET_PLIST_COMPONENT_LIST),$(eval $(call symbol_set_plist_template,$(symbolset))))

$(OBJPATH)/symbolsets.plist: $(SYMBOL_SET_PLIST_BUILD)
	$(_v)$(SOURCE)/generate_combined_symbolsets_plist.sh $@ $^ $(_vstdout)
	$(_v)$(PLUTIL) -convert binary1 -s $@

build_symbol_set_plists: $(KEXT_PLIST_BUILD) $(OBJPATH)/symbolsets.plist

$(TARGET)/allsymbols: $(OBJPATH)/$(KERNEL_FILE_NAME)
	$(_v)$(NM) -gj $< | sort -u > $@

check_all_exports: $(TARGET)/allsymbols $(KEXT_CREATE_SYMBOL_SET)
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(TARGET)/allsymbols				\
		$(foreach symbolset,$(filter-out Private,$(SYMBOL_COMPONENT_LIST)),	\
			-export $(SOURCE)/$(symbolset).exports		\
			-export $(SOURCE)/$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports)	\
		-output /dev/null $(_vstdout)
	$(_v)$(KEXT_CREATE_SYMBOL_SET)					\
		$(ARCH_FLAGS_$(CURRENT_ARCH_CONFIG))			\
		-import $(TARGET)/allsymbols				\
		$(foreach symbolset,$(filter-out Unsupported,$(SYMBOL_COMPONENT_LIST)),	\
			-export $(SOURCE)/$(symbolset).exports		\
			-export $(SOURCE)/$(symbolset).$(EXPORT_SOURCE_ARCH_CONFIG_LC).exports)	\
		-output /dev/null $(_vstdout)

$(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@$(LOG_SUPPORTED_KPI) "$(CURRENT_ARCH_CONFIG_LC)"
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) $(EXPORT_SOURCE_ARCH_CONFIG_LC) $@

$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME): $(EXPORTS_FILES)
	@$(LOG_SUPPORTED_KPI) "all"
	$(_v)$(SRCROOT)/config/list_supported.sh $(SOURCE) all $@

build_symbol_sets: check_all_exports $(SYMBOL_SET_BUILD) $(TARGET)/allsymbols \
			$(OBJPATH)/$(MD_SUPPORTED_KPI_FILENAME) \
			$(OBJPATH)/$(MI_SUPPORTED_KPI_FILENAME)

# Generate rules for symroot fat kexts with dependencies on every corresponding symbolset for each build config.
# This target must only run from do_config_install for a single build config after the do_config_all phases for
# all build configs have completed. This ensures every unique slice built by any config is pulled into the fat
# symbolset kext (note that not all slices are reflected as distinct xnu build config ARCHS!) (rdar://70703349)
define symroot_symbol_set_template
$$(SYMROOT_SYSTEM_KEXT_PATH)/$(1).kext/$(1): $$(addsuffix /config/$(1).symbolset, \
		$$(addprefix $$(OBJROOT)/,$$(foreach bc,$(BUILD_CONFIGS),$$(call function_convert_build_config_to_objdir,$$(bc)))))
	@$$(LOG_INSTALLSYM) "$$(Color0)symbolset $$(ColorF)$(1)"
	$$(_v)$$(MKDIR) $$(@D)
	$$(_v)$$(LIPO) -create `(echo $$^ | xargs -L 1 lipo -detailed_info) | \
		awk '/is architecture/ {s[$$$$6]=$$$$3} END {for (a in s) {print s[a]}}'` -output $$@ $$(_vstdout)

SYMROOT_INSTALL_KEXT_MACHO_FILES += $$(SYMROOT_SYSTEM_KEXT_PATH)/$(1).kext/$(1)
DSTROOT_INSTALL_KEXT_MACHO_FILES += $$(DSTROOT_SYSTEM_KEXT_PATH)/$(1).kext/$(1)
endef
$(foreach symbolset,$(SYMBOL_COMPONENT_LIST),$(eval $(call symroot_symbol_set_template,$(symbolset))))

$(SYMROOT_INSTALL_KEXT_PLISTS): $(SYMROOT)/% : $(TARGET)/%
	$(_v)$(MKDIR) $(@D)
	@$(LOG_INSTALLSYM) "$(Color0)kextplist $(ColorF)$*"
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

$(DSTROOT_INSTALL_KEXT_PLISTS): $(INSTALL_KEXT_DIR)/% : $(SYMROOT)/%
	$(_v)$(MKDIR) $(@D)
	@$(LOG_INSTALL) "$(Color0)kextplist $(ColorF)$*"
	$(_v)$(INSTALL) $(DATA_INSTALL_FLAGS) $< $@

$(DSTROOT_INSTALL_KEXT_MACHO_FILES): $(DSTROOT_SYSTEM_KEXT_PATH)/% : $(SYMROOT_SYSTEM_KEXT_PATH)/%
	$(_v)$(MKDIR) $(@D)
	@$(LOG_INSTALL) "$(Color0)symbolset $(ColorF)$(@F)"
	$(_v)$(INSTALL) $(EXEC_INSTALL_FLAGS) $< $@

$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME) $(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME): $(DSTROOT)/$(KRESDIR)/% : $(OBJPATH)/%
	$(_v)$(MKDIR) $(@D)
	@$(LOG_INSTALL) "$*"
	$(_v)$(INSTALL) $(INSTALL_FLAGS) $< $@

ifneq ($(RC_ProjectName),xnu_libraries)

do_build_all:: build_symbol_set_plists
do_config_all:: build_symbol_sets

ifneq ($(INSTALL_KASAN_ONLY),1)

do_config_install_primary:: \
				$(DSTROOT)/$(KRESDIR)/$(MD_SUPPORTED_KPI_FILENAME)

do_config_install:: \
				$(SYMROOT_INSTALL_KEXT_MACHO_FILES) \
				$(SYMROOT_INSTALL_KEXT_PLISTS) \
				$(DSTROOT_INSTALL_KEXT_MACHO_FILES) \
				$(DSTROOT_INSTALL_KEXT_PLISTS) \
				$(DSTROOT)/$(KRESDIR)/$(MI_SUPPORTED_KPI_FILENAME)
endif

else
# We are building XNU as a static library - avoid creating symbol sets
endif

$(OBJPATH)/all-kpi.exp: $(EXPORTS_FILES)
	$(_v)$(SOURCE)/generate_linker_exports.sh $@ $+ $(Kasan_EXPORTS) $(Kcov_EXPORTS)

$(OBJPATH)/all-alias.exp: $(EXPORTS_FILES)
	$(_v)$(SOURCE)/generate_linker_aliases.sh $@ $+ $(Kasan_EXPORTS) $(Kcov_EXPORTS)

do_build_all:: $(OBJPATH)/all-kpi.exp $(OBJPATH)/all-alias.exp

include $(MakeInc_rule)
include $(MakeInc_dir)

.PHONY: build_symbol_set_plists build_symbol_sets check_all_exports
