INCLUDED_TEST_SOURCE_DIRS += vm

# Revert to legacy vm_test suite until <rdar://problem/56675212> gets solved
EXCLUDED_SOURCES += vm/vm_allocation.c

EXCLUDED_SOURCES += jumbo_va_spaces_common.c

ifeq ($(PLATFORM),$(filter $(PLATFORM),iphoneos iPhoneOS XROS))
OTHER_TEST_TARGETS += vm/entitlement_increased_memory_limit vm/entitlement_increased_memory_limit_unentitled vm/entitlement_increased_debugging_memory_limit 

vm/entitlement_increased_memory_limit: CODE_SIGN_ENTITLEMENTS = vm/entitlement_increased_memory_limit.entitlements
vm/entitlement_increased_memory_limit: OTHER_CFLAGS += -DENTITLED=1 jumbo_va_spaces_common.c
vm/entitlement_increased_memory_limit: OTHER_LDFLAGS += -ldarwintest_utils memorystatus_assertion_helpers.c
vm/entitlement_increased_memory_limit: vm/entitlement_increased_memory_limit.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm/entitlement_increased_memory_limit_unentitled: OTHER_LDFLAGS += -ldarwintest_utils memorystatus_assertion_helpers.c
vm/entitlement_increased_memory_limit_unentitled: vm/entitlement_increased_memory_limit.c jumbo_va_spaces_common.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@

vm/entitlement_increased_debugging_memory_limit: CODE_SIGN_ENTITLEMENTS = vm/entitlement_increased_debugging_memory_limit.entitlements
vm/entitlement_increased_debugging_memory_limit: OTHER_CFLAGS += -DENTITLED_DEBUGGING=1 jumbo_va_spaces_common.c
vm/entitlement_increased_debugging_memory_limit: OTHER_LDFLAGS += -ldarwintest_utils memorystatus_assertion_helpers.c
vm/entitlement_increased_debugging_memory_limit: vm/entitlement_increased_memory_limit.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

# Patch bincompat entitlement increased memory limit test manually to report an iOS SDK.
# (Sorry to anyone looking at this in the future. If there's a better way of doing this, please do so)
ifeq ($(PLATFORM),XROS)
OTHER_TEST_TARGETS += vm/entitlement_increased_memory_limit_bincompat
vm/entitlement_increased_memory_limit_bincompat: CODE_SIGN_ENTITLEMENTS = vm/entitlement_increased_memory_limit.entitlements
vm/entitlement_increased_memory_limit_bincompat: OTHER_CFLAGS += -DENTITLED=1 -DBINCOMPAT=1 jumbo_va_spaces_common.c
vm/entitlement_increased_memory_limit_bincompat: OTHER_LDFLAGS += -ldarwintest_utils memorystatus_assertion_helpers.c 
vm/entitlement_increased_memory_limit_bincompat: vm/entitlement_increased_memory_limit.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@.xros
	$(shell /usr/bin/xcrun -sdk $(SDKROOT) -find vtool) -set-build-version 2 19.0 19.0 -replace -output $(SYMROOT)/$@ $(SYMROOT)/$@.xros
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;
endif

else
EXCLUDED_SOURCES += vm/entitlement_increased_memory_limit.c
endif

ifeq ($(IOS_TEST_COMPAT),YES)
OTHER_TEST_TARGETS += jumbo_va_spaces_28530648_unentitled jumbo_va_spaces_52551256 vm_phys_footprint_legacy vm/ios13extended_footprint vm/memorystatus_freeze_test vm/memorystatus_freeze_test_entitled vm/entitlement_internal_bands vm/entitlement_internal_bands_unentitled

jumbo_va_spaces_28530648: CODE_SIGN_ENTITLEMENTS = jumbo_va_spaces_28530648.entitlements
jumbo_va_spaces_28530648: OTHER_CFLAGS += -DENTITLED=1 -DTESTNAME=jumbo_va_spaces_28530648
jumbo_va_spaces_28530648: jumbo_va_spaces_common.c
jumbo_va_spaces_28530648: OTHER_LDFLAGS += -ldarwintest_utils
jumbo_va_spaces_28530648: OTHER_LDFLAGS += -sectcreate __TEXT __info_plist jumbo_va_spaces_28530648-identifier.plist

jumbo_va_spaces_52551256: CODE_SIGN_ENTITLEMENTS = jumbo_va_spaces_52551256.entitlements
jumbo_va_spaces_52551256: OTHER_CFLAGS += -DENTITLED=1 -DTESTNAME=jumbo_va_spaces_52551256
jumbo_va_spaces_52551256: OTHER_LDFLAGS += -ldarwintest_utils
jumbo_va_spaces_52551256: jumbo_va_spaces_28530648.c jumbo_va_spaces_common.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

jumbo_va_spaces_28530648_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
jumbo_va_spaces_28530648_unentitled: OTHER_CFLAGS += -DTESTNAME=jumbo_va_spaces_28530648_unentitled

jumbo_va_spaces_28530648_unentitled: jumbo_va_spaces_28530648.c jumbo_va_spaces_common.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@

vm/entitlement_internal_bands: CODE_SIGN_ENTITLEMENTS = vm/entitlement_internal_bands.entitlements
vm/entitlement_internal_bands: OTHER_CFLAGS += -DENTITLED=1
vm/entitlement_internal_bands: OTHER_LDFLAGS += -ldarwintest_utils
vm/entitlement_internal_bands: vm/entitlement_internal_bands.c memorystatus_assertion_helpers.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm/entitlement_internal_bands_unentitled: OTHER_LDFLAGS += -ldarwintest_utils
vm/entitlement_internal_bands_unentitled: vm/entitlement_internal_bands.c memorystatus_assertion_helpers.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $^ -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

vm/ios13extended_footprint: CODE_SIGN_ENTITLEMENTS = vm/ios13extended_footprint.entitlements
vm/ios13extended_footprint: vm/ios13extended_footprint.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements $(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$@;

vm_phys_footprint_legacy: OTHER_LDFLAGS += -framework CoreFoundation -framework IOSurface
vm_phys_footprint_legacy: OTHER_CFLAGS += -DLEGACY_FOOTPRINT_ENTITLED=1
vm_phys_footprint_legacy: CODE_SIGN_ENTITLEMENTS=./legacy_footprint.entitlement
vm_phys_footprint_legacy: vm_phys_footprint.c
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $< -o $(SYMROOT)/$@

endif

CUSTOM_TARGETS += vm/hello

vm/hello: vm/hello.c
	$(CC) $(LDFLAGS) $(CFLAGS) $< -o $(SYMROOT)/$@
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$@;

.PHONY: install-vm/hello
install-vm/hello: vm/hello
	mkdir -p $(INSTALLDIR)/vm
	cp $(SYMROOT)/vm/hello $(INSTALLDIR)/vm/

vm/vm_tainted_executable: vm/hello

vm/vm_ranges: CODE_SIGN_ENTITLEMENTS = ./vm/vm_ranges_entitlement.plist

vm_test_mach_map: CODE_SIGN_ENTITLEMENTS = ./vm_test_mach_map.plist

