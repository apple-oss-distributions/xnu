# example of how to run this from XNU root, see README.md:
#   make -C tests/unit SDKROOT=macosx.internal example_test_osfmk

PROJECT := xnu/unit_tests

ifdef BASEDSTROOT
override DSTROOT = $(BASEDSTROOT)
endif

DEVELOPER_DIR ?= $(shell xcode-select -p)
TOOLCHAIN_DIR := $(shell xcrun --sdk $(SDKROOT) --show-toolchain-path)
INVALID_ARCHS = $(filter-out arm64%,$(ARCH_CONFIGS))

.DEFAULT_GOAL := install

ORIG_SYMROOT := $(SYMROOT)

ifdef OBJROOT
XNU_OBJROOT := $(OBJROOT)
else
XNU_OBJROOT = $(XNU_ROOT)/BUILD/obj
endif

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.common

ifndef KERNEL_CONFIG
KERNEL_CONFIG = development
endif
ifndef PRODUCT_CONFIG
PRODUCT_CONFIG = j414c
endif

# find the name of the XNU library
# use make ... print-XXX to show any variable
XNU_ROOT := $(abspath $(SRCROOT)/../..)
KERNEL_CONFIG_UPPER := $(shell echo $(KERNEL_CONFIG) | tr '[:lower:]' '[:upper:]')
XNU_DETAILS := $(shell $(SRCROOT)/tools/get_target_details.py $(SDKROOT) $(PRODUCT_CONFIG))
XNU_ARCH := $(word 1,$(XNU_DETAILS))
XNU_KERNEL_PLATFORM := $(word 2,$(XNU_DETAILS))
XNU_KERNEL_PLATFORM_UPPER := $(shell echo $(XNU_KERNEL_PLATFORM) | tr '[:lower:]' '[:upper:]')
# in XNU makefile, KERNEL_FILE_NAME_PREFIX depends on the SDK platform, which is always MacOSX here
XNU_FILE_NAME_PREFIX := kernel
XNU_PLATFORM_FOR_CONFIG := $(word 3,$(XNU_DETAILS))

XNU_BUILD_DIR := $(XNU_OBJROOT)/$(KERNEL_CONFIG_UPPER)_$(XNU_ARCH)_$(XNU_KERNEL_PLATFORM_UPPER)
XNU_FILE_BASE := $(XNU_FILE_NAME_PREFIX).$(KERNEL_CONFIG).$(XNU_KERNEL_PLATFORM)
XNU_LIB_FILE_BASE := lib$(XNU_FILE_BASE)
XNU_LIB_FILE := $(XNU_BUILD_DIR)/$(XNU_LIB_FILE_BASE).a
XNU_LIB_DSYM := $(XNU_BUILD_DIR)/$(XNU_FILE_BASE).dSYM
XNU_ALIAS_LIST := $(XNU_BUILD_DIR)/all-alias.exp

# add Werror for consistency with the kernel
USE_WERROR := 1
ifneq ($(BUILD_WERROR),)
USE_WERROR := $(BUILD_WERROR)
endif
ifeq ($(USE_WERROR),1)
WERROR := -Werror
endif
OTHER_CFLAGS += $(WERROR)

# avoid annoyances
OTHER_CFLAGS += -Wno-missing-prototypes -Wno-unused-parameter -Wno-missing-variable-declarations
# darwintest config
DT_CFLAGS = -UT_NAMESPACE_PREFIX -DT_NAMESPACE_PREFIX=xnu -DT_LEAKS_DISABLE=1 -DBUILD_NO_STD_HEADERS -I$(DT_SYMLINKS_DIR)
OTHER_CFLAGS += $(DT_CFLAGS)
OTHER_CXXFLAGS += $(DT_CFLAGS)
OTHER_LDFLAGS += -ldarwintest_utils
# interpose header
INTERPOSE_CFLAGS = -I$(SDKROOT)/usr/local/include/mach-o
OTHER_CFLAGS += $(INTERPOSE_CFLAGS)
OTHER_CXXFLAGS += $(INTERPOSE_CFLAGS)
# we build with clang but XNU contains C++ so we add this manually
OTHER_LDFLAGS += -lc++

_v = $(if $(filter YES,$(or $(VERBOSE),$(RC_XBS))),,@)

LD := "$(shell xcrun -sdk "$(SDKROOT)" -find ld)"
DYLD_INFO := "$(shell xcrun -sdk "$(SDKROOT)" -find dyld_info)"
LIBTOOL := "$(shell xcrun -sdk "$(SDKROOT)" -find libtool)"
STRIP := "$(shell xcrun -sdk "$(SDKROOT)" -find strip)"
DSYMUTIL := "$(shell xcrun -sdk "$(SDKROOT)" -find dsymutil)"
NM := "$(shell xcrun -sdk "$(SDKROOT)" -find nm)"

# BUILD_LTO is disabled to avoid optimizations that would hinder interposing
XNU_MAKE_FLAGS := BUILD_LTO=0 PRODUCT_CONFIGS=$(PRODUCT_CONFIG) KERNEL_CONFIGS=$(KERNEL_CONFIG) PLATFORM_FOR_CONFIG=$(XNU_PLATFORM_FOR_CONFIG)
XNU_CFLAGS_EXTRA =
COVERAGE_FLAGS =

ifeq ($(BUILD_CODE_COVERAGE),1)
# make XNU build coverage
XNU_MAKE_FLAGS += BUILD_CODE_COVERAGE=1
# make mocks code not mock some coverage related llvm functions
COVERAGE_FLAGS += -D__BUILDING_FOR_COVERAGE__=1
endif # BUILD_CODE_COVERAGE

BUILD_SANITIZERS = 0
SANITIZERS_FLAGS =
ATTACH_SANITIZERS_SOURCES =
SANCOV_FLAG = -fsanitize-coverage=bb,no-prune,trace-pc-guard

ifeq ($(FIBERS_PREEMPTION),1)
# trace-loads,trace-stores depends on either trace-pc-guard or libfuzzer instrumentation
BUILD_SANCOV = 1
# compile with memory operations instrumentation
XNU_CFLAGS_EXTRA += -fsanitize-coverage=trace-loads,trace-stores
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_SANCOV_LOAD_STORES__=1
endif # FIBERS_PREEMPTION

ifeq ($(BUILD_LIBFUZZER),1)
BUILD_SANCOV = 1
# compile XNU with libfuzzer, redefine the sancov flag to use libfuzzer coverage collection
SANCOV_FLAG = -fsanitize=fuzzer-no-link
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_LIBFUZZER__=1
endif # BUILD_LIBFUZZER

ifeq ($(BUILD_ASAN),1)
BUILD_SANITIZERS = 1
# compile XNU with asan
# TODO: enable globals instrumentation and write a proper ignorelist for problematic global vars
XNU_CFLAGS_EXTRA += -fsanitize=address -mllvm -asan-globals=0
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_ASAN__=1
endif # BUILD_ASAN

ifeq ($(BUILD_UBSAN),1)
BUILD_SANITIZERS = 1
# compile XNU with ubsan
# TODO: add more ubsan support
XNU_CFLAGS_EXTRA += -fsanitize=signed-integer-overflow,shift,pointer-overflow,bounds,object-size,vla-bound,builtin
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_UBSAN__=1
endif # BUILD_UBSAN

ifeq ($(BUILD_TSAN),1)
BUILD_SANITIZERS = 1
# compile XNU with tsan
XNU_CFLAGS_EXTRA += -fsanitize=thread
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_TSAN__=1
endif # BUILD_TSAN

# SanitizerCoverage is used for preemption simulation
ifeq ($(BUILD_SANCOV),1)
BUILD_SANITIZERS = 1
# compile XNU with bb sancov
XNU_CFLAGS_EXTRA += $(SANCOV_FLAG) -fsanitize-coverage-ignorelist=$(SRCROOT)/tools/sanitizers-ignorelist
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_SANCOV__=1
endif # BUILD_SANCOV

ifeq ($(BUILD_SANITIZERS),1)
# include the ignorelist to disable instrumentation of some file/functions https://clang.llvm.org/docs/SanitizerSpecialCaseList.html
XNU_CFLAGS_EXTRA += -fsanitize-ignorelist=$(SRCROOT)/tools/sanitizers-ignorelist
# make mocks code aware of sanitizers runtime being linked
SANITIZERS_FLAGS += -D__BUILDING_WITH_SANITIZER__=1
ATTACH_SANITIZERS_SOURCES += mocks/san_attached.c
endif # BUILD_SANITIZERS

ifneq ($(strip $(XNU_CFLAGS_EXTRA)),)
# add CFLAGS_EXTRA to the XNU make flags if any, wrap between "" as XNU_CFLAGS_EXTRA contains spaces and replace inner " with \"
XNU_MAKE_FLAGS += CFLAGS_EXTRA="$(subst ",\",$(XNU_CFLAGS_EXTRA))"
endif

# sources for the mocks that are linked into the same .dylib as the XNU static lib
# fake_kinit.c needs to be first because it contains the initialization entry point
# These sources are compiled against OSFMK headers with no BSD headers options (for now)
ATTACH_XNU_DYLIB_SOURCES = mocks/fake_kinit.c \
                      mocks/fake_libsptm.c \
                      mocks/mock_3rd_party.c  \
                      mocks/mock_mem.c \
                      mocks/mock_attached.c \
                      $(ATTACH_SANITIZERS_SOURCES)

# sources that are added to the compilation of every test target
TEST_SIDE_SOURCES = mocks/dt_proxy.c

# Auto-discover all other osfmk mock sources for the mocks .dylib which overrides functions from XNU
MOCK_OSFMK_SOURCES := $(shell find mocks/osfmk -name '*.c')

# Auto-discover all other bsd mock sources for the mocks .dylib which overrides functions from XNU
MOCK_BSD_SOURCES := $(shell find mocks/bsd -name '*.c')

# Auto-discover sub-folders of of tests/unit/ which contains tests
UT_NON_TEST_DIRS := mocks tools build ipc/utils/
INCLUDED_TEST_SOURCE_DIRS := $(filter-out $(UT_NON_TEST_DIRS),$(patsubst %/,%,$(wildcard */)))

# --------------------- individual tests customization ----------------------------


# ---------------------------------------------------------------------------------

# we don't want to pass our arguments to the XNU makefile since that would confuse it, but we do want to pass any
# -j argument if it existed
unexport SRCROOT
unexport SDKROOT
unexport MAKEFLAGS
MKJOBS = $(filter --jobs=%,$(MAKEFLAGS))

.FORCE:
ifeq ($(SKIP_XNU),)
# The XNU make needs to run every time since if anything changed in XNU, we want to rebuild the tests
# This extra wait time can be skipped buy adding SKIP_XNU=1 to the make command line
$(XNU_LIB_FILE): .FORCE
	SDKROOT=$(SDKROOT) $(MAKE) -C $(XNU_ROOT) RC_ProjectName=xnu_libraries XNU_LibAllFiles=1 XNU_LibFlavour=UNITTEST SDKROOT=$(SDKROOT) $(XNU_MAKE_FLAGS) $(MKJOBS)
endif # SKIP_XNU

# Structure of unit-test linking:
# Mocking of XNU functions relies on the interposable functions mechanism which requires the interposed and interposable
# functions to be in different .dylibs
# - tester (executable)
#    - compiles tester.c
#    - statically linked to libdarwintest_stripped.a  (see explanation below)
#    - statically linked to libside.a
#    - [optional] dynamically linked to tester.pmocks.dylib
#          This comes first so it overrides mocks from libmocks.dylib
#    - dynamically linked to libmocks.dylib
#    - dynamically linked to libkernel.xxx.dylib
# - libside.a
#    - compiles mocks/dt_proxy.c  ($(TEST_SIDE_SOURCES)) which bridges PT_xxx calls from libmocks and libkernel
#      to libdarwintest. This is needed since the test executable is the only mach-o which links to libdarwintest
# - libmocks_bsd.a
#    - compiles bsd mocks - $(MOCK_BSD_SOURCES) files which contain T_MOCK_X() definitions to override functions from XNU
#      via interposable functions mechanism. These mocks are compiled against bsd headers.
# - libmocks_osfmk.a
#    - compiles osfmk mocks - $(MOCK_OSFMK_SOURCES) files which contain T_MOCK_X() definitions to override functions from XNU
#      via interposable functions mechanism. These mocks are compiled against osfmk headers.
# - libmocks.dylib
#    - links libmocks_bsd.a and libmocks_osfmk.a which contain T_MOCK_X() definitions to override functions from XNU
#      via the interposable functions mechanism.
#    - dynamically linked with libkernel.xxx.dylib
# - [optional] tester.pmocks.dylib
#    - compiles code extracted from tester.c in case it has a PMOCK_START..PMOCKS_END sections
#    - dynamically linked with libkernel.xxx.dylib
# - libkernel.xxx.dylib
#    - compiles mocks/xxx.c - $(ATTACH_XNU_DYLIB_SOURCES) files which contain dependencies needed for linking the XNU static library
#    - statically linked to libkernel.xxx.prelinked.a
#    - makes all functions interposable so that internal calls are routed to mocks
# - libkernel.xxx.prelinked.a
#    - This is the same content as libkernel.xxx.a, passed through "ld -r" so that some symbols that are also
#      defined in libc can be unexported, so that anything outside XNU (i.e. mock and darwintest code) doesn't end up
#      calling them. e.g get_pid()
# - libkernel.xxx.a
#    - This is the static lib produced by XNU make which contains all of the XNU code.
# - libfuzzer.dylib
#    - The libfuzzer static lib in the SDK is linked to a dylib to avoid to statically link it to the test executable using XNU symbols

# flags that .c files under MODULE (osfmk/bsd) are built with. MODULE should be defined per target
MODULE_CFLAGS = $(shell $(SRCROOT)/tools/quote_defines.py $(XNU_BUILD_DIR)/$(MODULE)/$(KERNEL_CONFIG_UPPER)/.CFLAGS) -I$(XNU_BUILD_DIR)/$(MODULE)/$(KERNEL_CONFIG_UPPER) $(MODULE_FLAG) $(SANITIZERS_FLAGS)
MODULE_CXXFLAGS = $(shell $(SRCROOT)/tools/quote_defines.py $(XNU_BUILD_DIR)/$(MODULE)/$(KERNEL_CONFIG_UPPER)/.CXXFLAGS) -I$(XNU_BUILD_DIR)/$(MODULE)/$(KERNEL_CONFIG_UPPER) $(MODULE_FLAG) $(SANITIZERS_FLAGS)
OSFMK_CFLAGS = $(shell $(SRCROOT)/tools/quote_defines.py $(XNU_BUILD_DIR)/osfmk/$(KERNEL_CONFIG_UPPER)/.CFLAGS) -I$(XNU_BUILD_DIR)/osfmk/$(KERNEL_CONFIG_UPPER)
BSD_CFLAGS = $(shell $(SRCROOT)/tools/quote_defines.py $(XNU_BUILD_DIR)/bsd/$(KERNEL_CONFIG_UPPER)/.CFLAGS) -I$(XNU_BUILD_DIR)/bsd/$(KERNEL_CONFIG_UPPER)
MOCKS_CFLAGS = $(INTERPOSE_CFLAGS) $(COVERAGE_FLAGS) $(SANITIZERS_FLAGS)
MOCKS_OSFMK_CFLAGS = $(OSFMK_CFLAGS) $(MOCKS_CFLAGS)
MOCKS_BSD_CFLAGS = $(BSD_CFLAGS) $(MOCKS_CFLAGS)

# We need to link the darwintest headers from an empty folder and include from there since we can't add their
# original folder as -I since that would allow XNU headers to include SDK headers.
DT_SYMLINKS_DIR := $(OBJROOT)/darwintest_headers
DT_ORIG_DIR := $(SDKROOT)/usr/local/include
# Target to check if the sdk changed. content of the file is the path to the last sdk used for building
$(OBJROOT)/sdk_updated: .FORCE
	$(_v)if [ ! -f $(OBJROOT)/sdk_updated ] || [ "$$(cat $(OBJROOT)/sdk_updated)" != "$(SDKROOT)" ]; then \
	    echo $(SDKROOT) > $(OBJROOT)/sdk_updated; \
	fi
# Do we need to update the darwintest headers symlinks?
$(DT_SYMLINKS_DIR): $(DT_ORIG_DIR)/darwintest.h $(OBJROOT)/sdk_updated
	$(_v)mkdir -p $(DT_SYMLINKS_DIR)
	$(_v)for file in $(DT_ORIG_DIR)/darwintest*; do ln -sfn "$${file}" $(DT_SYMLINKS_DIR); done

# libdarwintest.a is built with normal system headers so its debug-info contains type definitions which conflict with types in XNU
# for example 'vm_map_t' is defined as `mach_port_t` (uint) instead of a struct pointer.
# This is a problem for lldb macros which get confused when trying to evaluate expressions based on these types.
# To avoid this we strip the debug info from lidarwintest and link with stripped version. There doesn't seem to be a way
# to remove just the type information or to make lldb ignore this type information.
# libdarwintest still has symbols to show in the backtrace, but no line-number information. Stepping into libdarwintest
# code is not typically needed so this doesn't affect the normal user debugging experience.
DT_ORIG_LIB := $(SDKROOT)/usr/local/lib/libdarwintest.a
DT_STRIPPED_LIB := $(OBJROOT)/libdarwintest_stripped.a
$(DT_STRIPPED_LIB): $(DT_ORIG_LIB) $(OBJROOT)/sdk_updated
	$(_v)$(STRIP) -S $(DT_ORIG_LIB) -o $(DT_STRIPPED_LIB)
# make the libdarwintest makefile not do -ldarwintest
DT_LDFLAGS :=

# The LD invocation below can't get the arch and platform from the prelinked.a file so we need this empty object
# to carry this information
ARCH_DEF_OBJ := $(OBJROOT)/arch_def.o
$(ARCH_DEF_OBJ): $(XNU_LIB_FILE)
	$(_v)$(CC) -c -x c /dev/null -o $@ $(CFLAGS)

SPTM_LIB := $(SDKROOT)/usr/local/lib/kernel/platform/libsptm_xnu.a
# this creates a dummy executable with libsptm_xnu.a so that the xbs dependency analysis know to build xnu_unittests after libsptm was installed
DUMMY_SPTM_EXE := $(OBJROOT)/ut_dummy_sptm
$(DUMMY_SPTM_EXE): $(SPTM_LIB) $(OBJROOT)/sdk_updated $(ARCH_DEF_OBJ)
	$(_v)echo "int start() { return 0; }" > $(OBJROOT)/dummy_sptm_start.c
	$(_v)$(CC) $(CFLAGS) $(OBJROOT)/dummy_sptm_start.c -Wl,-e,_start -Wl,-pie -nostdlib -Wl,-kernel -static -Wl,-force_load,$(SPTM_LIB) -o $@

# we need libfuzzer as dylib to have it using libc symbols instead of libxnu ones
LIBFUZZER_FILE := $(shell find "$(TOOLCHAIN_DIR)/usr/lib/clang" -name "libclang_rt.fuzzer_osx.a" -print -quit 2>/dev/null)
ifeq ($(LIBFUZZER_FILE),)
  $(error Could not automatically find libFuzzer (libclang_rt.fuzzer_*.a) in toolchain path: $(TOOLCHAIN_DIR))
endif
LIBFUZZER_PRELINKED := $(OBJROOT)/libfuzzer.prelinked.a
# make sure to export the sanitizercoverage symbols when prelinking
$(LIBFUZZER_PRELINKED): $(ARCH_DEF_OBJ)
	$(_v)$(LD) $(ARCH_DEF_OBJ) -r -all_load $(LIBFUZZER_FILE) -o $@ -exported_symbols_list $(SRCROOT)/tools/libfuzzer.export
LIBFUZZER_DYLIB := $(SYMROOT)/libfuzzer.dylib
$(LIBFUZZER_DYLIB): $(LIBFUZZER_PRELINKED)
	$(_v)$(CC) $(CFLAGS) -lc++ -dynamiclib $(LIBFUZZER_PRELINKED) -install_name @rpath/libfuzzer.dylib -o $@ -U _LLVMFuzzerTestOneInput
MAY_LINK_LIBFUZZER =
# we need to link libxnu and libmocks to libfuzzer.dylib to avoid symbol binding to the ubsan dylib
ifeq ($(BUILD_LIBFUZZER),1)
	MAY_LINK_LIBFUZZER = $(LIBFUZZER_DYLIB)
endif

XNU_LIB_PRELINKED := $(OBJROOT)/$(XNU_LIB_FILE_BASE).prelinked.a
$(XNU_LIB_PRELINKED): $(XNU_LIB_FILE) $(SRCROOT)/tools/xnu_lib.unexport $(ARCH_DEF_OBJ)
	$(_v)$(LD) -r $(ARCH_DEF_OBJ) -all_load $(XNU_LIB_FILE) -o $@ -unexported_symbols_list $(SRCROOT)/tools/xnu_lib.unexport -alias_list $(XNU_ALIAS_LIST)

XNU_LIB_DYLIB := $(SYMROOT)/$(XNU_LIB_FILE_BASE).dylib

$(XNU_LIB_DYLIB): $(XNU_LIB_PRELINKED) $(ATTACH_XNU_DYLIB_SOURCES) $(DT_SYMLINKS_DIR) $(MAY_LINK_LIBFUZZER)
	$(_v)$(CC) $(MOCKS_OSFMK_CFLAGS) $(CFLAGS) -dynamiclib $(ATTACH_XNU_DYLIB_SOURCES) -Wl,-all_load,$(XNU_LIB_PRELINKED) -lc++ -Wl,-undefined,dynamic_lookup -Wl,-interposable -install_name @rpath/$(XNU_LIB_FILE_BASE).dylib $(MAY_LINK_LIBFUZZER) -o $@
ifneq ($(NO_LLDBMACROS),1)
	$(_v)cp -R $(XNU_LIB_DSYM)/Contents/Resources/Python $@.dSYM/Contents/Resources/
	$(_v)mv $@.dSYM/Contents/Resources/Python/{,lib}$(XNU_FILE_NAME_PREFIX)_$(KERNEL_CONFIG).py
endif

# Do we need to update the unimplemented functions mock?
$(OBJROOT)/func_unimpl.inc: $(XNU_LIB_DYLIB)
	$(_v)echo "// Generated from undefined imports from: $(XNU_LIB_DYLIB)" > $@
	$(_v)$(DYLD_INFO) -imports $(XNU_LIB_DYLIB) | grep "flat-namespace" | awk '{print "UNIMPLEMENTED(" substr($$2, 2) ")"}' >> $@
# The xnu dylib is linked with -undefined dynamic_lookup so that it's able to find undefined symbols at load time
# These are symbols that come from libsptm_xnu.a and libTightbeam.a. They still need to have an implementation for load
# to succeeds so this gets the list of undefined symbols and defines them in the mocks dylib
# use awk to discard the first underscore prefix of each symbol and wrap with UNIMPLEMENTED() macro expected in mock_unimpl.c

MOCKS_OSFMK_LIB := $(SYMROOT)/libmocks_osfmk.a
MOCKS_OSFMK_OBJECTS := $(patsubst $(OBJROOT)/mocks/%,$(OBJROOT)/%,$(patsubst %.c,$(OBJROOT)/%.o,$(MOCK_OSFMK_SOURCES)))
$(OBJROOT)/osfmk/%.o: mocks/osfmk/%.c $(XNU_LIB_DYLIB) $(OBJROOT)/func_unimpl.inc
	$(_v)mkdir -p $(OBJROOT)/osfmk/fibers
	$(_v)$(CC) $(MOCKS_OSFMK_CFLAGS) -I$(OBJROOT) -DUT_BUILDING_LIBMOCKS $(CFLAGS) -c $< -o $@

$(MOCKS_OSFMK_LIB): $(MOCKS_OSFMK_OBJECTS)
	$(_v)$(LIBTOOL) -static $^ -o $@

MOCKS_BSD_LIB := $(SYMROOT)/libmocks_bsd.a
MOCKS_BSD_OBJECTS := $(patsubst mocks/bsd/%.c,$(OBJROOT)/bsd/%.o,$(MOCK_BSD_SOURCES))
$(OBJROOT)/bsd/%.o:  mocks/bsd/%.c $(XNU_LIB_DYLIB) $(OBJROOT)/func_unimpl.inc
	$(_v)mkdir -p $(OBJROOT)/bsd
	$(_v)$(CC) $(MOCKS_BSD_CFLAGS) -I$(OBJROOT) -DUT_BUILDING_LIBMOCKS $(CFLAGS) -c $< -o $@

$(MOCKS_BSD_LIB): $(MOCKS_BSD_OBJECTS)
	$(_v)$(LIBTOOL) -static $^ -o $@

MOCKS_DYLIB := $(SYMROOT)/libmocks.dylib
LIBMOCKS_MOCKSYMS := $(OBJROOT)/libmocks.mocksyms
$(MOCKS_DYLIB): $(XNU_LIB_DYLIB) $(MOCKS_BSD_LIB) $(MOCKS_OSFMK_LIB) $(OBJROOT)/func_unimpl.inc $(MAY_LINK_LIBFUZZER)
	$(_v)$(CC) $(MOCKS_OSFMK_CFLAGS) $(CFLAGS) -I$(OBJROOT) $(XNU_LIB_DYLIB) -Wl,-all_load,$(MOCKS_BSD_LIB) -Wl,-all_load,$(MOCKS_OSFMK_LIB) -dynamiclib -MJ $@.json -install_name @rpath/libmocks.dylib $(MAY_LINK_LIBFUZZER) -o $@
	$(_v)$(DSYMUTIL) $@ -o $@.dSYM
	$(_v)$(NM) -gjU $@ | grep "_MOCK_" > $(LIBMOCKS_MOCKSYMS)
# $(CC) ... -install_name makes the test executables which link to these .dylibs find them in the same folder rather than the
# folder the .dylibs happen to be built at. The path is relative to rpath and rpath is defined by the executable
# itself to be to root of test executables, see below.
# $(DSYMUNIT) - The clang driver only invokes ld and doesn't generate the dsym on it's own
# $(NM) ... > .mocksyms lists all the mock functions created in libmocks.dylib this will be used when creating the .pmocks.dylib
# to check for double-defined mocks.

SIDE_LIB := $(OBJROOT)/libside.a
TEST_SIDE_OBJ := $(foreach source,$(TEST_SIDE_SOURCES),$(OBJROOT)/$(notdir $(basename $(source))).o)
$(TEST_SIDE_OBJ): $(TEST_SIDE_SOURCES) $(DT_SYMLINKS_DIR) $(XNU_LIB_DYLIB)
	$(_v)$(CC) $(MOCKS_OSFMK_CFLAGS) $(CFLAGS) $(DT_CFLAGS) -c $< -o $@
$(SIDE_LIB): $(TEST_SIDE_OBJ)
	$(_v)$(LIBTOOL) -static $< -o $@

# this creates a shell script for running all the unit-tests on-desk (build all using target 'install'
.PHONY: run_unittests
install: run_unittests
RUN_UT_SCRIPT := $(SYMROOT)/run_unittests.sh
RUN_UT_LIST := $(SYMROOT)/run_unittests.targets
run_unittests: $(RUN_UT_SCRIPT)
$(RUN_UT_SCRIPT): $(SRCROOT)/tools/make_run_unittests.py
	$(SRCROOT)/tools/make_run_unittests.py "$(TEST_TARGETS)" $@ $(RUN_UT_LIST)
	chmod a+x $@

# inform the dt makefile that these need to be installed along with the test executables
CUSTOM_TARGETS += $(XNU_LIB_DYLIB) $(MOCKS_DYLIB) $(DUMMY_SPTM_EXE) $(LIBFUZZER_DYLIB) $(RUN_UT_SCRIPT)
install-$(XNU_LIB_DYLIB): $(XNU_LIB_DYLIB)
	mkdir -p $(INSTALLDIR)
	cp $< $(INSTALLDIR)/
install-$(MOCKS_DYLIB): $(MOCKS_DYLIB)
	mkdir -p $(INSTALLDIR)
	cp $< $(INSTALLDIR)/
install-$(DUMMY_SPTM_EXE): $(DUMMY_SPTM_EXE)
	echo "not copying $(DUMMY_SPTM_EXE)"
install-$(LIBFUZZER_DYLIB): $(LIBFUZZER_DYLIB)
	mkdir -p $(INSTALLDIR)
	cp $< $(INSTALLDIR)/
install-$(RUN_UT_SCRIPT): $(RUN_UT_SCRIPT)
	mkdir -p $(INSTALLDIR)
	cp $< $(INSTALLDIR)/
	cp $(RUN_UT_LIST) $(INSTALLDIR)/

OTHER_LDFLAGS += $(XNU_LIB_DYLIB) $(MOCKS_DYLIB) $(PMOCKS_DYLIB_IF_EXIST) -Wl,-force_load,$(SIDE_LIB)

# add libfuzzer flags and rpath as the xnu and mocks lib will be not located in the same directory
fuzzing/%: OTHER_CFLAGS += -fsanitize=fuzzer-no-link
# linking libfuzzer.dylib for fuzzing harnesses first as it is important to prioritize its symbols
fuzzing/%: OTHER_LDFLAGS := $(LIBFUZZER_DYLIB) $(OTHER_LDFLAGS)

include $(DEVELOPER_DIR)/AppleInternal/Makefiles/darwintest/Makefile.targets

# ---- pmocks ----
# A test can define private mocks (pmocks), i.e. mocks that are going to be defined only when it runs.
# This is done by adding a section sorrounded by PMOCKS_START..PMOCKS_END and adding T_MOCK_PRIVATE()
# definitions in it.
# This is different from using T_MOCK_SET_CALLBACK() where the mock is defined in the global libmocks
# and the test supplies a function that will be called when the mock is called.
# These are two mechanisms to do the same thing - allow the test to provide its own implementation for a mock
# pmocks have the added benefit of avoiding possible code conflicts when adding to the global mocks library
# in tests/unit/mocks/
#
# dyld-interposing works only between two .dylibs
# We extract the code between PMOCKS_START..PMOCKS_END from test.c into a separate test.pmocks.c file
# and build it into test.pmocks.dylib which the test executable depends on

.SECONDEXPANSION:
# This expands to the name of the pmocks.dylib if the test.c includes PMOCKS_START or to nothing if not
# This is added to the test executable dependencies
# The above .SECONDEXPANSION: is needed for this to expand correctly
CHECK_PMOCKS = $(shell \
  for f in $*.c $*.cpp; do \
    [ -f "$$f" ] && grep -q 'PMOCKS_START' "$$f" && { echo $(SYMROOT)/$*.pmocks.dylib; break; }; \
  done)

PMOCKS_DYLIBS_c := $(patsubst %,$(SYMROOT)/%.pmocks.dylib,$(TEST_TARGETS_c))
PMOCKS_DYLIBS_cxx := $(patsubst %,$(SYMROOT)/%.pmocks.dylib,$(TEST_TARGETS_cxx))

# recipe for generating test.pmocks.dylib
# - verify there is a PMOCKS_END (after the above check found we have a PMOCKS_START
# - run test.c through the preprocessor so that conditionally compiled code can be removed to produce test.pmocks.i
#    - MODULE_CFLAGS is available here due to the dependency from the target
# - extract only the sections inside PMOCKS_START..PMOCKS_END. There can be multiple such sections to produce test.pmocks.c
# - build test.pmocks.dylib from the extracted code
# - verify the mocks produced in the built dylib do not intersect with the mocks in libmocks.dylib
#   - Having the same mock in two dylibs causes hard to predict bugs
define PMOCKS_RECIPE
	$(_v)grep -q 'PMOCKS_END' $< || (echo "Error: Missing PMOCKS_END in $<" >&2; exit 1)
	$(_v)$(CC) -E -P $(MODULE_CFLAGS) $(CFLAGS) $(DT_CFLAGS) $(INTERPOSE_CFLAGS) -I$(OBJROOT) -DUT_EXTRACTING_PMOCKS $< -o $(OBJROOT)/$(subst /,__,$*).pmocks.i
	$(_v)awk '/^PMOCKS_START/{f=1;next}/^PMOCKS_END/{f=0}f' < $(OBJROOT)/$(subst /,__,$*).pmocks.i > $(OBJROOT)/$(subst /,__,$*).pmocks.c
	$(_v)rm -f $(OBJROOT)/$(subst /,__,$*).pmocks.i
	$(_v)mkdir -p $(@D)
	$(_v)$(CC) $(MODULE_CFLAGS) $(MOCKS_CFLAGS) -DUT_BUILDING_PMOCKS $(CFLAGS) -I$(OBJROOT) $(XNU_LIB_DYLIB) -include mocks/mock_dynamic.h -dynamiclib -install_name @rpath/$*.pmocks.dylib $(OBJROOT)/$(subst /,__,$*).pmocks.c -o $@
	$(_v)$(NM) -gjU $@ | grep "_MOCK_" > $(OBJROOT)/$(subst /,__,$*).mocksyms
	$(_v)SYM_INTERSECT=$$(comm -12 $(LIBMOCKS_MOCKSYMS) $(OBJROOT)/$(subst /,__,$*).mocksyms) || exit 1; \
    	if [ -n "$$SYM_INTERSECT" ]; then \
    		echo "Error: pmocks section in '$*' defines a mock that's already defined in libmocks.dylib. consider using T_MOCK_SET_PERM_FUNC() instead."; \
    		echo "$$SYM_INTERSECT"; \
    		rm -f $@; \
    		exit 1; \
    	fi
endef

# Separate rules for .c and .cpp since they depend on a different pattern
$(PMOCKS_DYLIBS_c): $(SYMROOT)/%.pmocks.dylib: %.c $(XNU_LIB_DYLIB) $(MOCKS_DYLIB) $(DT_SYMLINKS_DIR)
	$(PMOCKS_RECIPE)
$(PMOCKS_DYLIBS_cxx): $(SYMROOT)/%.pmocks.dylib: %.cpp $(XNU_LIB_DYLIB) $(MOCKS_DYLIB) $(DT_SYMLINKS_DIR)
	$(PMOCKS_RECIPE)

# This is added to OTHER_LDFLAGS so that the test-executable links to the pmocks.dylib if it exists
PMOCKS_DYLIB_IF_EXIST = $(shell [ -f $(SYMROOT)/$*.pmocks.dylib ] && echo $(SYMROOT)/$*.pmocks.dylib)

.PHONY: install_pmocks
install: install_pmocks
install_pmocks: $(TEST_TARGETS)
	@mkdir -p $(INSTALLDIR)
	@for t in $(TEST_TARGETS); do \
		pmock=$$t.pmocks.dylib; \
		if [ -f "$(SYMROOT)/$$pmock" ]; then \
		    echo "installing pmock $(SYMROOT)/$$pmock to dir $(INSTALLDIR)/$$(dirname $$pmock)"; \
		    mkdir -p $(INSTALLDIR)/$$(dirname $$pmock); \
			cp $(SYMROOT)/$$pmock $(INSTALLDIR)/$$(dirname $$pmock); \
		fi; \
	done


# ---- determining the module for the test ----
# Every unit-test target needs to define a target-specific variable named UT_MODULE so that MODULE_CFLAGS is defined
# This is parsed from the .c file that needs to have a line like: #define UT_MODULE osfmk
# The clang invocation may produce errors due to missing include folders but it still generates the #defines list.
define assign_module
$(1): MODULE ?= $(shell for f in $(1).c $(1).cpp; do \
    [ -f $$f ] && $(CC) -E -dM $$f 2>/dev/null | grep -m1 '^#define UT_MODULE ' | awk '{print $$3}' && break; \
done)
endef
$(foreach target, $(TEST_TARGETS), $(eval $(call assign_module, $(target), $(target))))
# In the case no UT_MODULE was found, this will trigger an error in std_safe.h
MODULE_FLAG = -DUT_MODULE=$(if $(strip $(MODULE)),$(MODULE),-1)

# All test targets depend on the XNU lib
$(TEST_TARGETS): $(XNU_LIB_DYLIB) $(MOCKS_DYLIB) $(SIDE_LIB) $(LIBFUZZER_DYLIB) $(DT_STRIPPED_LIB) $$(CHECK_PMOCKS)

# When the test executalbe is in a sub-folder, it's rpath needs to point back to the root of all
# test executables. This is done by appending as many ".." to @executable_path as there are levels of sub-directories
define make_rpath
@executable_path$(shell \
  dir=$$(dirname "$1"); \
  if [ "$$dir" != "." ]; then \
    echo "$$dir" | sed 's|[^/][^/]*|..|g' | sed 's|^|/|'; \
  fi)
endef
# this sets the CFLAGS for building the test to be the same as files in it's UT_MODULE
$(TEST_TARGETS): OTHER_CFLAGS += $(MODULE_CFLAGS) -MJ $(OBJROOT)/$(subst /,__,$@).json -rpath $(call make_rpath,$@)
# C++ files get both CFLAGS and CXXFLAGS
$(TEST_TARGETS): OTHER_CXXFLAGS += $(MODULE_CXXFLAGS) $(MODULE_CFLAGS) -MJ $(OBJROOT)/$(subst /,__,$@).json -rpath $(call make_rpath,$@)

# This is for creating a new version of $(XNU_ROOT)/compile_commands.json that includes
# the test and mock files. It's used by IDEs for understanding the code
.PHONY: cmds_json proj_xcode proj_vscode proj_clion
cmds_json:
	$(SRCROOT)/tools/merge_cmds_json.py $(XNU_ROOT) $(XNU_BUILD_DIR) $(OBJROOT)

proj_xcode: cmds_json
	$(SRCROOT)/tools/generate_ut_proj.py xcode
proj_vscode: cmds_json
	$(SRCROOT)/tools/generate_ut_proj.py vscode
proj_clion: cmds_json
	$(SRCROOT)/tools/generate_ut_proj.py clion

