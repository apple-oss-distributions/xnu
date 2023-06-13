include ../Makefile.common

CFLAGS := -Os -g $(ARCH_FLAGS) -isysroot $(SDKROOT) -isystem $(SDKROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

DSTROOT?=$(shell /bin/pwd)
SYMROOT?=$(shell /bin/pwd)

DEBUG:=0

$(DSTROOT)/zn: zero-to-n.c
	$(CC) $(CFLAGS) -Wall zero-to-n.c -o $(SYMROOT)/$(notdir $@) -DDEBUG=$(DEBUG) -ggdb
	if [ ! -e $@ ]; then ditto $(SYMROOT)/$(notdir $@) $@; fi
	env CODESIGN_ALLOCATE=$(CODESIGN_ALLOCATE) \
	    $(CODESIGN) -s - --entitlements entitlements.plist $@


clean:
	rm -rf $(DSTROOT)/zn $(SYMROOT)/*.dSYM $(SYMROOT)/zn
