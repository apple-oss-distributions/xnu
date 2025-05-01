# -*- mode: makefile;-*-
#
# Copyright (C) 1999-2020 Apple Inc. All rights reserved.
#
# MakeInc.cmd contains command paths for use during
# the build, as well as make fragments and text
# strings that may be evaluated as utility functions.
#

#
# Commands for the build environment
#

#
# Build Logging and Verbosity
#

ifeq ($(RC_XBS),YES)
	VERBOSE = YES
else
	VERBOSE = NO
endif

BASH = bash

ECHO = echo

ERR = $(ECHO) > /dev/stderr
PRINTF = printf

QUIET ?= 0
ifneq ($(QUIET),0)
	PRINTF = printf > /dev/null
	ifeq ($(VERBOSE),YES)
		override VERBOSE = NO
	endif
endif

# Helper functions for logging operations.
LOG_PFX_LEN = 15
LOG_PFX_LEN_ADJ = $(LOG_PFX_LEN)
LOG = $(PRINTF) "$2%$4s$(Color0) $3%s$(Color0)\n" "$1"

CONCISE ?= 0
ifneq ($(CONCISE),0)
	# Concise logging puts all logs on the same line (CSI K to clear and
	# carriage return).
	LOG = $(PRINTF) "$2%$4s$(Color0) $3%s$(Color0)\033[K\r" "$1"
endif

_LOG_COMP = $(call LOG,$1,$(ColorC),$(ColorF),$(LOG_PFX_LEN_ADJ))
_LOG_HOST = $(call LOG,$1,$(ColorH),$(ColorF),$(LOG_PFX_LEN))
_LOG_HOST_LINK = $(call LOG,$1,$(ColorH),$(ColorLF),$(LOG_PFX_LEN))

# Special operations.
LOG_LDFILELIST = $(call LOG,LDFILELIST,$(ColorL),$(ColorLF),$(LOG_PFX_LEN_ADJ))
LOG_MIG = $(call LOG,MIG,$(ColorM),$(ColorF),$(LOG_PFX_LEN_ADJ))
LOG_LD = $(call LOG,LD,$(ColorL),$(ColorF),$(LOG_PFX_LEN_ADJ))
LOG_ALIGN = $(call LOG,--------->,$(Color0),$(Color0),$(LOG_PFX_LEN))

# Compiling/machine-specific operations.
LOG_CC = $(call _LOG_COMP,CC)
LOG_CXX = $(call _LOG_COMP,C++)
LOG_AS = $(call _LOG_COMP,AS)
LOG_LTO = $(call _LOG_COMP,LTO)
LOG_SYMBOLSET = $(call _LOG_COMP,SYMSET)
LOG_SYMBOLSETPLIST = $(call _LOG_COMP,SYMSETPLIST)
LOG_VERIFIER = $(call _LOG_COMP,VERIFIER)

# Host-side operations.
LOG_TIGHTBEAMC = $(call _LOG_HOST,TIGHTBEAMC)
LOG_IIG = $(call _LOG_HOST,IIG)
LOG_HOST_CC = $(call _LOG_HOST,CC)
LOG_HOST_LD = $(call _LOG_HOST,LD)
LOG_HOST_CODESIGN = $(call _LOG_HOST,CODESIGN)
LOG_HOST_BISON = $(call _LOG_HOST,BISON)
LOG_HOST_FLEX = $(call _LOG_HOST,FLEX)
LOG_INSTALL = $(call _LOG_HOST,INSTALL)
LOG_INSTALLVARIANT = $(call _LOG_HOST,INSTALLVARIANT)
LOG_INSTALLSYM = $(call _LOG_HOST,INSTALLSYM)
LOG_INSTALLHDR = $(call _LOG_HOST,INSTALLHDR)
LOG_INSTALLMACROS = $(call _LOG_HOST,INSTALLMACROS)
LOG_INSTALLPY = $(call _LOG_HOST,INSTALLPY)
LOG_MAN = $(call _LOG_HOST,MAN)
LOG_MANLINK = $(call _LOG_HOST,MANLINK)
LOG_ALIAS = $(call _LOG_HOST,ALIAS)
LOG_STRIP = $(call _LOG_HOST,STRIP)
LOG_DSYMUTIL = $(call _LOG_HOST,DSYMUTIL)
LOG_LIBTOOL = $(call _LOG_HOST,LIBTOOL)
LOG_FILEPREP = $(call _LOG_HOST,FILEPREP)

# Host-side linking operations.
LOG_GENASSYM = $(call _LOG_HOST_LINK,GENASSYM)
LOG_GENERATE= $(call _LOG_HOST_LINK,GENERATE)
LOG_CTFCONVERT = $(call _LOG_HOST_LINK,CTFCONVERT)
LOG_CTFMERGE = $(call _LOG_HOST_LINK,CTFMERGE)
LOG_CTFINSERT = $(call _LOG_HOST_LINK,CTFINSERT)
LOG_DSYMUTIL = $(call _LOG_HOST_LINK,DSYMUTIL)
LOG_SUPPORTED_KPI = $(call _LOG_HOST_LINK,SUPPORTED_KPI)


ifeq ($(VERBOSE),YES)
	_v =
	_vstdout =
	_vstderr =
	XCRUN = /usr/bin/xcrun -verbose
else
	_v = @
	_vstdout = > /dev/null
	_vstderr = 2> /dev/null
	XCRUN = /usr/bin/xcrun
endif

VERBOSE_GENERATED_MAKE_FRAGMENTS = NO

#
# Defaults
#

SDKROOT ?= macosx
HOST_SDKROOT ?= macosx

# SDKROOT may be passed as a shorthand like "iphoneos.internal". We
# must resolve these to a full path and override SDKROOT.

ifeq ($(origin SDKROOT_RESOLVED),undefined)
export SDKROOT_RESOLVED := $(shell $(XCRUN) -sdk $(SDKROOT) -show-sdk-path)
ifeq ($(strip $(SDKROOT)_$(SDKROOT_RESOLVED)),/_)
export SDKROOT_RESOLVED := /
endif
endif
override SDKROOT = $(SDKROOT_RESOLVED)

ifeq ($(origin HOST_SDKROOT_RESOLVED),undefined)
export HOST_SDKROOT_RESOLVED := $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -show-sdk-path)
ifeq ($(strip $(HOST_SDKROOT_RESOLVED)),)
export HOST_SDKROOT_RESOLVED := /
endif
endif
override HOST_SDKROOT = $(HOST_SDKROOT_RESOLVED)

ifeq ($(origin SDKVERSION),undefined)
     export SDKVERSION := $(shell $(XCRUN) -sdk $(SDKROOT) -show-sdk-version)
endif

ifeq ($(origin PLATFORM),undefined)
	export PLATFORMPATH := $(shell $(XCRUN) -sdk $(SDKROOT) -show-sdk-platform-path)
	export PLATFORM := $(shell echo $(PLATFORMPATH) | sed 's,^.*/\([^/]*\)\.platform$$,\1,' | sed 's,\.[^.]*$$,,')
	ifeq ($(PLATFORM),)
		export PLATFORM := MacOSX
	else ifeq ($(shell echo $(PLATFORM) | tr A-Z a-z),watchos)
		export PLATFORM := WatchOS
	endif
endif

ifeq ($(PLATFORM),DriverKit)
	ifeq ($(origin COHORT_SDKROOT_RESOLVED),undefined)
		SDK_NAME = $(notdir $(SDKROOT))
		export COHORT_NAME := $(shell echo $(SDK_NAME) | sed -e 's|DriverKit.\([a-zA-Z]*\)$(SDKVERSION)\([.Internal]*\).sdk|\1\2|g' | tr A-Z a-z)
		export COHORT_SDKROOT_RESOLVED := $(shell $(XCRUN) -sdk $(COHORT_NAME) -show-sdk-path)
		ifeq ($(strip $(COHORT_SDKROOT_RESOLVED)),)
		export COHORT_SDKROOT_RESOLVED := $(SDKROOT_RESOLVED)
		endif
	endif
	override COHORT_SDKROOT = $(COHORT_SDKROOT_RESOLVED)
	export PLATFORMPATH = $(shell $(XCRUN) -sdk $(COHORT_SDKROOT) -show-sdk-platform-path)
	export PLATFORM := DriverKit
	export DRIVERKIT ?= 1
	export DRIVERKITROOT ?= /System/DriverKit
	export DRIVERKITRUNTIMEROOT = $(DRIVERKITROOT)/Runtime
else
	override COHORT_SDKROOT = $(SDKROOT)
endif

ifeq ($(PLATFORM),MacOSX)
	ifeq (DriverKit,$(shell echo $(SDKROOT_RESOLVED) | sed 's|^.*/\([^./1-9]*\)\(\.[^./1-9]*\)\{0,1\}[1-9][^/]*\.sdk$$|\1|'))
		export PLATFORM := DriverKit
		export DRIVERKIT ?= 1
		export DRIVERKITROOT ?= /System/DriverKit
		export DRIVERKITRUNTIMEROOT = $(DRIVERKITROOT)/Runtime
	endif
endif

ifeq ($(PLATFORM),ExclaveKit)
	ifeq ($(origin COHORT_SDKROOT_RESOLVED),undefined)
		SDK_NAME = $(notdir $(SDKROOT))
		export COHORT_NAME := $(shell echo $(SDK_NAME) | sed -e 's|ExclaveKit.\([a-zA-Z]*\)$(SDKVERSION)\([.Internal]*\).sdk|\1\2|g' | tr A-Z a-z)
		export COHORT_SDKROOT_RESOLVED := $(shell $(XCRUN) -sdk $(COHORT_NAME) -show-sdk-path)
		ifeq ($(strip $(COHORT_SDKROOT_RESOLVED)),)
		export COHORT_SDKROOT_RESOLVED := $(SDKROOT_RESOLVED)
		endif
	endif
	override COHORT_SDKROOT = $(COHORT_SDKROOT_RESOLVED)
	export PLATFORMPATH = $(shell $(XCRUN) -sdk $(COHORT_SDKROOT) -show-sdk-platform-path)
	export PLATFORM := ExclaveKit
	export EXCLAVEKIT ?= 1
	export EXCLAVEKITROOT ?= /System/ExclaveKit
endif

ifeq ($(PLATFORM),ExclaveCore)
	ifeq ($(origin COHORT_SDKROOT_RESOLVED),undefined)
		SDK_NAME = $(notdir $(SDKROOT))
		export COHORT_NAME := $(shell echo $(SDK_NAME) | sed -e 's|ExclaveCore.\([a-zA-Z]*\)$(SDKVERSION)\([.Internal]*\).sdk|\1\2|g' | tr A-Z a-z)
		export COHORT_SDKROOT_RESOLVED := $(shell $(XCRUN) -sdk $(COHORT_NAME) -show-sdk-path)
		ifeq ($(strip $(COHORT_SDKROOT_RESOLVED)),)
		export COHORT_SDKROOT_RESOLVED := $(SDKROOT_RESOLVED)
		endif
	endif
	override COHORT_SDKROOT = $(COHORT_SDKROOT_RESOLVED)
	export PLATFORMPATH = $(shell $(XCRUN) -sdk $(COHORT_SDKROOT) -show-sdk-platform-path)
	export PLATFORM := ExclaveCore
	export EXCLAVECORE ?= 1
	export EXCLAVECOREROOT ?= /System/ExclaveCore
endif

# CC/CXX get defined by make(1) by default, so we can't check them
# against the empty string to see if they haven't been set
ifeq ($(origin CC),default)
	export CC := $(shell $(XCRUN) -sdk $(SDKROOT) -find clang)
endif
ifeq ($(origin CXX),default)
	export CXX := $(shell $(XCRUN) -sdk $(SDKROOT) -find clang++)
endif
ifeq ($(origin MIG),undefined)
	export MIG := $(shell $(XCRUN) -sdk $(SDKROOT) -find mig)
endif
ifeq ($(origin MIGCOM),undefined)
	export MIGCOM := $(shell $(XCRUN) -sdk $(SDKROOT) -find migcom)
endif
ifeq ($(origin MIGCC),undefined)
	export MIGCC := $(CC)
endif
ifeq ($(origin IIG),undefined)
	export IIG := $(shell $(XCRUN) -sdk $(SDKROOT) -find iig)
endif
ifeq ($(origin STRIP),undefined)
	export STRIP := $(shell $(XCRUN) -sdk $(SDKROOT) -find strip)
endif
ifeq ($(origin LIPO),undefined)
	export LIPO := $(shell $(XCRUN) -sdk $(SDKROOT) -find lipo)
endif
ifeq ($(origin LIBTOOL),undefined)
	export LIBTOOL := $(shell $(XCRUN) -sdk $(SDKROOT) -find libtool)
endif
ifeq ($(origin OTOOL),undefined)
	export OTOOL := $(shell $(XCRUN) -sdk $(SDKROOT) -find otool)
endif
ifeq ($(origin NM),undefined)
	export NM := $(shell $(XCRUN) -sdk $(SDKROOT) -find nm)
endif
ifeq ($(origin UNIFDEF),undefined)
	export UNIFDEF := $(shell $(XCRUN) -sdk $(SDKROOT) -find unifdef)
endif
ifeq ($(origin DSYMUTIL),undefined)
	export DSYMUTIL := $(shell $(XCRUN) -sdk $(SDKROOT) -find dsymutil)
endif
ifeq ($(origin NMEDIT),undefined)
	export NMEDIT := $(shell $(XCRUN) -sdk $(SDKROOT) -find nmedit)
endif
ifeq ($(origin GIT),undefined)
	export GIT := $(shell $(XCRUN) -sdk $(SDKROOT) -find git)
endif
ifeq ($(origin SCAN_BUILD),undefined)
	export SCAN_BUILD := $(shell $(XCRUN) -sdk $(SDKROOT) -find scan-build 2> /dev/null)
endif
ifeq ($(origin CTFINSERT),undefined)
	export CTFINSERT := $(shell $(XCRUN) -sdk $(SDKROOT) -find ctf_insert 2> /dev/null)
endif
ifeq ($(origin CTFCONVERT),undefined)
	export CTFCONVERT := $(shell $(XCRUN) -sdk $(SDKROOT) -find ctfconvert 2> /dev/null)
endif
ifeq ($(origin CTFMERGE),undefined)
	export CTFMERGE := $(shell $(XCRUN) -sdk $(SDKROOT) -find ctfmerge 2> /dev/null)
	ifeq (,$(wildcard $(CTFMERGE)))
		export DO_CTFMERGE := 0
	endif
endif
ifeq ($(origin CTFDUMP),undefined)
	export CTFDUMP := $(shell $(XCRUN) -sdk $(SDKROOT) -find ctfdump 2> /dev/null)
endif
ifeq ($(origin DOCC),undefined)
	export DOCC := $(shell $(XCRUN) -sdk $(SDKROOT) -find docc 2> /dev/null)
endif
ifeq ($(origin PYTHON),undefined)
	export PYTHON := $(shell $(XCRUN) -sdk $(SDKROOT) -find python3 2> /dev/null)
endif
ifeq ($(origin OBJDUMP),undefined)
	export OBJDUMP := $(shell $(XCRUN) -sdk $(SDKROOT) -find objdump 2> /dev/null)
endif

#
# Platform options
#
SUPPORTED_EMBEDDED_PLATFORMS := iPhoneOS iPhoneOSNano tvOS AppleTVOS WatchOS BridgeOS
SUPPORTED_SIMULATOR_PLATFORMS := iPhoneSimulator iPhoneNanoSimulator tvSimulator AppleTVSimulator WatchSimulator


SUPPORTED_PLATFORMS := MacOSX DriverKit ExclaveKit ExclaveCore $(SUPPORTED_SIMULATOR_PLATFORMS) $(SUPPORTED_EMBEDDED_PLATFORMS)

# Platform-specific tools
EDM_DBPATH ?= $(PLATFORMPATH)/usr/local/standalone/firmware/device_map.db

# Scripts or tools we build ourselves
#
# setsegname - Rename segments in a Mach-O object file
# kextsymboltool - Create kext pseudo-kext Mach-O kexts binaries
# decomment - Strip out comments to detect whether a file is comments-only
# installfile - Atomically copy files, esp. when multiple architectures
#               are trying to install the same target header
# replacecontents - Write contents to a file and update modtime *only* if
#                   contents differ
# vm_sanitize_enforcement - Reject MIG files that use types that do not enforce
#                           sanitization for VM inputs
#
SEG_HACK = $(OBJROOT)/SETUP/setsegname/setsegname
KEXT_CREATE_SYMBOL_SET = $(OBJROOT)/SETUP/kextsymboltool/kextsymboltool
DECOMMENT = $(OBJROOT)/SETUP/decomment/decomment
NEWVERS = $(SRCROOT)/config/newvers.pl
INSTALL = $(OBJROOT)/SETUP/installfile/installfile
REPLACECONTENTS = $(OBJROOT)/SETUP/replacecontents/replacecontents
VM_SANITIZE_ADOPTION_CHECK = $(SRCROOT)/tools/vm_sanitize_enforcement.py

# Standard BSD tools
RM = /bin/rm -f
RMDIR = /bin/rmdir
CP = /bin/cp
MV = /bin/mv
LN = /bin/ln -fs
CAT = /bin/cat
MKDIR = /bin/mkdir -p
CHMOD = /bin/chmod
FIND = /usr/bin/find
XARGS = /usr/bin/xargs
PAX = /bin/pax
BASENAME = /usr/bin/basename
DIRNAME = /usr/bin/dirname
TR = /usr/bin/tr
TOUCH = /usr/bin/touch
SLEEP = /bin/sleep
AWK = /usr/bin/awk
SED = /usr/bin/sed
PLUTIL = /usr/bin/plutil
PATCH = /usr/bin/patch
GREP = /usr/bin/grep

#
# Command to generate host binaries. Intentionally not
# $(CC), which controls the target compiler
#
ifeq ($(origin HOST_OS_VERSION),undefined)
	export HOST_OS_VERSION	:= $(shell sw_vers -productVersion)
endif
ifeq ($(origin HOST_CC),undefined)
	export HOST_CC		:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find clang)
endif
ifeq ($(origin HOST_FLEX),undefined)
	export HOST_FLEX	:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find flex)
endif
ifeq ($(origin HOST_BISON),undefined)
	export HOST_BISON	:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find bison)
endif
ifeq ($(origin HOST_GM4),undefined)
	export HOST_GM4		:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find gm4)
endif
ifeq ($(origin HOST_CODESIGN),undefined)
	export HOST_CODESIGN	:= /usr/bin/codesign
endif
ifeq ($(origin HOST_CODESIGN_ALLOCATE),undefined)
	export HOST_CODESIGN_ALLOCATE	:= $(shell $(XCRUN) -sdk $(HOST_SDKROOT) -find codesign_allocate)
endif

#
# The following variables are functions invoked with "call", and thus
# behave similarly to externally compiled commands
#

# $(1) is an expanded kernel config from a TARGET_CONFIGS_UC tuple
# $(2) is an expanded arch config from a TARGET_CONFIGS_UC tuple
# $(3) is an expanded machine config from a TARGET_CONFIGS_UC tuple
_function_create_build_configs_join = $(strip $(1))^$(strip $(2))^$(strip $(3))

# $(1) is an un-expanded kernel config from a TARGET_CONFIGS_UC tuple
# $(2) is an un-expanded arch config from a TARGET_CONFIGS_UC tuple
# $(3) is an un-expanded machine config from a TARGET_CONFIGS_UC tuple
_function_create_build_configs_do_expand =          $(call _function_create_build_configs_join, \
							   $(if $(filter DEFAULT,$(1)), \
								$(DEFAULT_KERNEL_CONFIG), \
								$(1) \
							    ), \
							   $(if $(filter DEFAULT,$(2)), \
								$(DEFAULT_ARCH_CONFIG), \
								$(2) \
							    ), \
							   $(if $(filter DEFAULT,$(3)), \
								$(if $(filter DEFAULT,$(2)), \
								     $(DEFAULT_$(DEFAULT_ARCH_CONFIG)_MACHINE_CONFIG), \
								     $(DEFAULT_$(strip $(2))_MACHINE_CONFIG) \
								), \
								$(3) \
							    ) \
						     )

# $(1) is an un-expanded TARGET_CONFIGS_UC list, which must be consumed
#      3 elements at a time
function_create_build_configs = $(sort \
					$(strip \
						 $(call _function_create_build_configs_do_expand, \
							$(word 1,$(1)), \
							$(word 2,$(1)), \
							$(word 3,$(1)), \
						  ) \
						 $(if $(word 4,$(1)), \
						      $(call function_create_build_configs, \
							     $(wordlist 4,$(words $(1)),$(1)) \
						       ), \
						  ) \
					  ) \
				   )

# Similar to build configs, but alias configs are a 4-tuple

# $(1) is an expanded kernel config from a TARGET_CONFIGS_ALIASES_UC tuple
# $(2) is an expanded arch config from a TARGET_CONFIGS_ALIASES_UC tuple
# $(3) is an expanded kernel machine config from a TARGET_CONFIGS_ALIASES_UC tuple
# $(4) is an expanded SoC platform config from a TARGET_CONFIGS_ALIASES_UC tuple,
#      which should be an alias of $(3)
_function_create_alias_configs_join = $(strip $(1))^$(strip $(2))^$(strip $(3))^$(strip $(4))

_function_create_alias_configs_do_expand =	    $(call _function_create_alias_configs_join, \
							   $(if $(filter DEFAULT,$(1)), \
							        $(DEFAULT_KERNEL_CONFIG), \
								$(1) \
							    ), \
							   $(if $(filter DEFAULT,$(2)), \
								$(DEFAULT_ARCH_CONFIG), \
								$(2) \
							    ), \
							   $(3), \
							   $(4) \
						     )

function_create_alias_configs = $(sort \
					$(strip \
						 $(call _function_create_alias_configs_do_expand, \
							$(word 1,$(1)), \
							$(word 2,$(1)), \
							$(word 3,$(1)), \
							$(word 4,$(1)), \
						  ) \
						 $(if $(word 5,$(1)), \
						      $(call function_create_alias_configs, \
							     $(wordlist 5,$(words $(1)),$(1)) \
						       ), \
						  ) \
					 ) \
				 )

# $(1) is a fully-expanded kernel config
# $(2) is a fully-expanded arch config
# $(3) is a fully-expanded machine config. "NONE" is not represented in the objdir path
function_convert_target_config_uc_to_objdir = $(if $(filter NONE,$(3)),$(strip $(1))_$(strip $(2)),$(strip $(1))_$(strip $(2))_$(strip $(3)))

# $(1) is a fully-expanded build config (like "RELEASE^X86_64^NONE")
function_convert_build_config_to_objdir = $(call function_convert_target_config_uc_to_objdir, \
						 $(word 1,$(subst ^, ,$(1))), \
						 $(word 2,$(subst ^, ,$(1))), \
						 $(word 3,$(subst ^, ,$(1))) \
					   )

# $(1) is a fully-expanded build config (like "RELEASE^X86_64^NONE")
function_extract_kernel_config_from_build_config  = $(word 1,$(subst ^, ,$(1)))
function_extract_arch_config_from_build_config    = $(word 2,$(subst ^, ,$(1)))
function_extract_machine_config_from_build_config = $(word 3,$(subst ^, ,$(1)))

#
# Returns build config if both architecture and kernel configuration match.
#
#   $(1) - list of build configs
#   $(1) - architecture
#   $(2) - kernel configuration

function_match_build_config_for_architecture_and_kernel_config = $(strip \
			    $(foreach build_config, $(1), \
			      $(if \
				$(and \
				  $(filter $(2), $(call function_extract_arch_config_from_build_config, $(build_config))), \
				  $(filter $(3), $(call function_extract_kernel_config_from_build_config, $(build_config)))), \
			      $(build_config), )))

#
# Returns build config if kernel configuration matches.
#
#   $(1) - list of build configs
#   $(2) - kernel configuration

function_match_build_config_for_kernel_config = $(strip \
			    $(foreach build_config, $(1), \
			      $(if \
				  $(filter $(2), $(call function_extract_kernel_config_from_build_config, $(build_config))), \
			      $(build_config), )))

# $(1) is an input word
# $(2) is a list of colon-separate potential substitutions like "FOO:BAR BAZ:QUX"
# $(3) is a fallback if no substitutions were made
function_substitute_word_with_replacement = $(strip $(if $(2),								\
							 $(if $(filter $(word 1,$(subst :, ,$(word 1,$(2)))),$(1)),	\
							      $(word 2,$(subst :, ,$(word 1,$(2)))),		\
							      $(call function_substitute_word_with_replacement,$(1),$(wordlist 2,$(words $(2)),$(2)),$(3))), \
							 $(3)								\
						     )									\
					     )

# You can't assign a variable to an empty space without these
# shenanigans
empty :=
space := $(empty) $(empty)

# Arithmetic
# $(1) is the number to increment
NUM32 = x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x
increment = $(words x $(wordlist 1,$(1),$(NUM32)))
decrement = $(words $(wordlist 2,$(1),$(NUM32)))

# Create a sequence from 1 to $(1)
# F(N) = if N > 0: return F(N-1) + "N" else: return ""
sequence = $(if $(wordlist 1,$(1),$(NUM32)),$(call sequence,$(call decrement,$(1))) $(1),)

# Reverse a list of words in $(1)
reverse = $(if $(word 2,$(1)),$(call reverse,$(wordlist 2,$(words $(1)),$(1)))) $(word 1,$(1))

# vim: set ft=make:
