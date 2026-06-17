INCLUDED_TEST_SOURCE_DIRS += containment_vessels

OTHER_TEST_TARGETS += containment_vessels/exception_send_allowed_entitled
containment_vessels/exception_send_allowed_entitled: CODE_SIGN_ENTITLEMENTS = containment_vessels/entitlements/entitlement_true_set_exception.plist
containment_vessels/exception_send_allowed_entitled: OTHER_CFLAGS += -DSET_EXCEPTION_ENTITLED
containment_vessels/exception_send_allowed_entitled: OTHER_CFLAGS += -I $(OBJROOT)
containment_vessels/exception_send_allowed_entitled: excserver ipc/ipc_utils.c exc_helpers.c containment_vessels/exception_send_allowed.c $(OBJROOT)/excserver.c
	$(call DARWIN_COMPILE_C_TEST,$^,$@)


# Reusable Darwin test compilation functions - TODO: de-dupe this and the copy in ipc/Makefile
define DARWIN_MKDIR
	$(shell [ -d "$(SYMROOT)/$(dir $(1))" ] || mkdir -p $(SYMROOT)/$(dir $(1)))
endef

define DARWIN_COMPILE
	$(CC) $(DT_CFLAGS) $(OTHER_CFLAGS) $(CFLAGS) $(DT_LDFLAGS) $(OTHER_LDFLAGS) $(LDFLAGS) $(foreach f,$(filter %.c %.m %.cpp %.mm %.a,$(1)),$(abspath $(f))) -o $(SYMROOT)/$(2)
endef

define DARWIN_CODESIGN
	@if [ -f "$(CODE_SIGN_ENTITLEMENTS)" ]; then \
		echo $(CODESIGN) --force --sign - --timestamp=none --entitlements $(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS) $(SYMROOT)/$(1); \
		env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none --entitlements "$(SRCROOT)/$(CODE_SIGN_ENTITLEMENTS)" $(SYMROOT)/$(1); \
	else \
		echo $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$(1); \
		env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) $(CODESIGN) --force --sign - --timestamp=none $(SYMROOT)/$(1); \
	fi
endef

# Complete compilation function for easy use
# Usage: $(call DARWIN_COMPILE_C_TEST,sources,target)
define DARWIN_COMPILE_C_TEST
	$(call DARWIN_MKDIR,$(2))
	$(call DARWIN_COMPILE,$(1),$(2))
	$(call DARWIN_CODESIGN,$(2))
endef

# Install rule for all containment_vessels targets to create directories before use
install-containment_vessels/%: | $(INSTALLDIR)/containment_vessels
	cp $(SYMROOT)/containment_vessels/$* $(INSTALLDIR)/containment_vessels/

$(OBJROOT)/containment_vessels:
	mkdir -p $(OBJROOT)/containment_vessels
$(SYMROOT)/containment_vessels:
	mkdir -p $(SYMROOT)/containment_vessels
$(INSTALLDIR)/containment_vessels:
	mkdir -p $(INSTALLDIR)/containment_vessels

containment_vessels/entitlement_true_test: CODE_SIGN_ENTITLEMENTS = containment_vessels/entitlements/entitlement_true.plist

containment_vessels/entitlement_false_test: CODE_SIGN_ENTITLEMENTS = containment_vessels/entitlements/entitlement_false.plist

containment_vessels/ipc_notification: CODE_SIGN_ENTITLEMENTS = containment_vessels/entitlements/ipc_notification.entitlements
containment_vessels/ipc_notification: ipc/ipc_utils.c

containment_vessels/exception_send_allowed: CODE_SIGN_ENTITLEMENTS = containment_vessels/entitlements/entitlement_true.plist
containment_vessels/exception_send_allowed: ipc/ipc_utils.c exc_helpers.c excserver
containment_vessels/exception_send_allowed: OTHER_CFLAGS += $(OBJROOT)/excserver.c -I $(OBJROOT)

