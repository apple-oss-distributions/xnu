include ../Makefile.common

SYMROOT?=$(shell /bin/pwd)

CFLAGS	:=-g -isysroot $(SDKROOT) -I$(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

DSTROOT?=$(shell /bin/pwd)
SRCROOT?=$(shell /bin/pwd)

SOURCES := sets.c pool.c tags.c
ARCH_64_TARGETS := $(addprefix $(DSTROOT)/, sets64 pool64 tags64)

TARGETS := $(if $(ARCH_CONFIGS_64), $(ARCH_64_TARGETS))


all:	$(TARGETS)

.SECONDEXPANSION:
$(ARCH_64_TARGETS): $(DSTROOT)/%: $(SRCROOT)/$$(subst 64,,%).c
	$(CC) $(CFLAGS) $(ARCH_FLAGS_64) $< -o $(SYMROOT)/$(notdir $@) # 64-bit fat
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi

clean:
	rm -f $(TARGETS)
	rm -rf $(SYMROOT)/*.dSYM
