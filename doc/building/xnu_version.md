# XNU Version Number #

Incorporating the version number into xnu's build.

## Overview

The first line of the generated file `$(OBJROOT)/xnuVersion` contains the
version number for the kernel being built. All other instances of the kernel
version in xnu are derived from that file.

## Generating the XNU version number ##

The buildsystem (`makedefs/MakeInc.kernel`) generates the `xnuVersion` file by
deriving the xnu version from the SDK or KDK that xnu is being built against.
The xnu version number is read from the `CFBundleVersion` property of
the `System/Library/Extensions/System.kext/Info.plist` file in the SDK or KDK.

### Customizing the XNU version number ###

The derivation above can be bypassed and the xnu version customized by setting
the `RC_DARWIN_KERNEL_VERSION` variable in the environment or overriding it on
the `make` command line.


## Format of the XNU version number ##

The format of the version number must conform to the version resource format
as described in [TN1132]
(https://web.archive.org/web/20090330032438/http://developer.apple.com/technotes/tn/tn1132.html).

In particular, the string is formatted as: `J[.N[.R[S[L]]]]`, where:

* `J` represents the kernel major version number (integer)
* `N` represents the kernel minor version number (integer)
* `R` represents the kernel revision number (integer)
* `S` represents the kernel build stage (one of `d`, `a`, `b`, or `r`)
* `L` represents the kernel pre-release level (integer)

## Using the XNU version number ##

The correct way to make use of the kernel version within kernel code or a
kext is to include `<libkern/version.h>`.  This header contains defines that
can be used for build-time version logic and prototypes for variables that can
be used for run-time version logic.

