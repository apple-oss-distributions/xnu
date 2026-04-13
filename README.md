# What is XNU?

XNU kernel is part of the Darwin operating system for use in macOS and iOS operating systems. XNU is an acronym for X is Not Unix.
XNU is a hybrid kernel combining the Mach kernel developed at Carnegie Mellon University with components from FreeBSD and a C++ API for writing drivers called IOKit.
XNU runs on x86_64 and ARM64 for both single processor and multi-processor configurations.

## The XNU Source Tree

* `config` - configurations for exported apis for supported architecture and platform
* `SETUP` - Basic set of tools used for configuring the kernel, versioning and kextsymbol management.
* `EXTERNAL_HEADERS` - Headers sourced from other projects to avoid dependency cycles when building. These headers should be regularly synced when source is updated.
* `libkern` - C++ IOKit library code for handling of drivers and kexts.
* `libsa` -  kernel bootstrap code for startup
* `libsyscall` - syscall library interface for userspace programs
* `libkdd` - source for user library for parsing kernel data like kernel chunked data.
* `makedefs` - top level rules and defines for kernel build.
* `osfmk` - Mach kernel based subsystems
* `pexpert` - Platform specific code like interrupt handling, atomics etc.
* `security` - Mandatory Access Check policy interfaces and related implementation.
* `bsd` - BSD subsystems code
* `tools` - A set of utilities for testing, debugging and profiling kernel.

## How to Build XNU

### Prerequisites for External Developers

If you are building XNU outside of Apple's internal development environment, you will need to set up additional dependencies first.

#### Download and Install Xcode

Ensure you have the Xcode installed that is aligned with the OS version you want to build (for example, Xcode 15.4 for MacOS 15.4). Download from:
* App Store, or
* https://developer.apple.com/download/all/ (requires Apple Developer account)

To select a specific version of Xcode:

```sh
sudo xcode-select -s path/to/Xcode.app/Contents/Developer
xcrun -sdk macosx -show-sdk-path
```

#### Download and Install the Kernel Debug Kit (KDK)

**This step is required for building on Apple silicon.** If you are building only for Intel, you can skip this step.

1. Download the KDK from https://developer.apple.com/download/all/ (requires Apple Developer account)
2. Search for "Kernel Debug Kit" and download the package matching your exact macOS version (you can find this in Settings > General > About)
3. Install the package. It will be installed to `/Library/Developer/KDKs/KDK_{ver}_{build}.kdk`
4. Save the path for later use:

```sh
export KDK=/Library/Developer/KDKs/KDK_{ver}_{build}.kdk
```

#### Download and Build XNU Dependencies

The following dependencies must be built and installed before building XNU:

- DTrace (this is optional)
- AvailabilityVersions
- libdispatch
- xnu headers

The versions you need can be downloaded from https://opensource.apple.com/releases/

##### Build CTF Tools from dtrace

```sh
tar zxf dtrace-{version}.tar.gz
cd dtrace-{version}
xcodebuild install -sdk macosx -target ctfconvert \
  -target ctfdump -target ctfmerge \
  ARCHS='x86_64 arm64' VALID_ARCHS='x86_64 arm64' DSTROOT=$PWD/dst
export TOOLCHAIN=$(cd $(xcrun -sdk macosx -show-sdk-platform-path)/../../Toolchains/XcodeDefault.xctoolchain && pwd)
sudo ditto "$PWD/dst/$TOOLCHAIN" "$TOOLCHAIN"
cd ..
```

##### Install AvailabilityVersions

```sh
tar zxf AvailabilityVersions-{version}.tar.gz
cd AvailabilityVersions-{version}
make install
sudo ditto "$PWD/dst/usr/local/libexec" \
  "$(xcrun -sdk macosx -show-sdk-path)/usr/local/libexec"
cd ..
```

##### Install XNU Headers

```sh
tar zxf xnu-{version}.tar.gz
cd xnu-{version}
make SDKROOT=macosx ARCH_CONFIGS="X86_64 ARM64" installhdrs
sudo ditto "$PWD/BUILD/dst" "$(xcrun -sdk macosx -show-sdk-path)"
cd ..
```

##### Build libfirehose from libdispatch

```sh
tar zxf libdispatch-{version}.tar.gz
cd libdispatch-{version}
xcodebuild install -sdk macosx ARCHS='x86_64 arm64e' \
  VALID_ARCHS='x86_64 arm64e' -target libfirehose_kernel \
  PRODUCT_NAME=firehose_kernel DSTROOT=$PWD/dst
sudo ditto "$PWD/dst/usr/local" \
  "$(xcrun -sdk macosx -show-sdk-path)/usr/local"
cd ..
```

### Building a `DEVELOPMENT` Kernel

The xnu make system can build kernel based on `KERNEL_CONFIGS` & `ARCH_CONFIGS` variables as arguments.
Here is the syntax:

```text
make SDKROOT=<sdkroot> ARCH_CONFIGS=<arch> KERNEL_CONFIGS=<variant>
```

Where:

* `<sdkroot>`: path to macOS SDK on disk. (defaults to `/`)
* `<variant>`: can be `debug`, `development`, `release`, `profile` and configures compilation flags and asserts throughout kernel code.
* `<arch>`: can be valid arch to build for. (E.g. `X86_64`)

#### For Internal Developers

To build a kernel for the same architecture as running OS, just type

```text
make SDKROOT=macosx.internal
```

Additionally, there is support for configuring architectures through `ARCH_CONFIGS` and kernel configurations with `KERNEL_CONFIGS`.

```text
make SDKROOT=macosx.internal ARCH_CONFIGS=X86_64 KERNEL_CONFIGS=DEVELOPMENT
make SDKROOT=macosx.internal ARCH_CONFIGS=X86_64 KERNEL_CONFIGS="RELEASE DEVELOPMENT DEBUG"
```

#### For External Developers

##### Building for Intel Macs

```sh
cd xnu-{version}
make SDKROOT=macosx ARCH_CONFIGS=X86_64 KERNEL_CONFIGS=RELEASE
```

##### Building for Apple Silicon Macs

```sh
cd xnu-{version}
make SDKROOT=macosx KDKROOT=${KDK} \
  TARGET_CONFIGS="RELEASE ARM64 {PLATFORM}"
```

The `{PLATFORM}` should be set based on your machine. A table of platform and associated Mac Models can be found at the end of this document.

Example for MacBookAir10,1:

```sh
make SDKROOT=macosx KDKROOT=${KDK} TARGET_CONFIGS="RELEASE ARM64 T8101"
```

##### Build Options

* Speed up link: add `BUILD_LTO=0`
* Build development kernel: replace `RELEASE` with `DEVELOPMENT`
* Colorful output: add `LOGCOLORS=y`
* Concise output: add `CONCISE=1`

> Note: By default, the architecture is set to the build machine's architecture, and the default kernel config is set to build for `DEVELOPMENT`.

This will also create a bootable image, kernel.[config],  and a kernel binary
with symbols, kernel.[config].unstripped.

To install the kernel into a DSTROOT, use the `install_kernels` target:

```text
make install_kernels DSTROOT=/tmp/xnu-dst
```

For a more satisfying kernel debugging experience, with access to all
local variables and arguments, but without all the extra check of the
DEBUG kernel, add something like the following to your make command:

```text
CFLAGS_DEVELOPMENTARM64="-O0 -g -DKERNEL_STACK_MULTIPLIER=2"
CXXFLAGS_DEVELOPMENTARM64="-O0 -g -DKERNEL_STACK_MULTIPLIER=2"
```

Remember to replace `DEVELOPMENT` and `ARM64` with the appropriate build and platform.

> Extra Flags: You can pass additional flags to the C compiler at the command line with the `EXTRA_CFLAGS` build setting. These flags are appended to the base `CFLAGS`, and the default value for the setting is an empty string.
>
> This setting allows you to e.g. selectively turn on debugging code that is guarded by a preprocessor macro. Example usage...
>
> ```text
> make SDKROOT=macosx.internal PRODUCT_CONFIGS=j314s
> EXTRA_CFLAGS='-DKERNEL_STACK_MULTIPLIER=2'
> ```


* To build with RELEASE kernel configuration

    ```text
    make KERNEL_CONFIGS=RELEASE SDKROOT=/path/to/SDK
    ```

### Building FAT Kernel Binary

Define architectures in your environment or when running a make command.

```text
make ARCH_CONFIGS="X86_64" exporthdrs all
```



### Other Makefile Options

* $ make MAKEJOBS=-j8    # this will use 8 processes during the build. The default is 2x the number of active CPUS.
* $ make -j8             # the standard command-line option is also accepted
* $ make -w              # trace recursive make invocations. Useful in combination with VERBOSE=YES
* $ make BUILD_LTO=0     # build without LLVM Link Time Optimization
* $ make BOUND_CHECKS=0  # disable -fbound-attributes for this build
* $ make REMOTEBUILD=user@remotehost # perform build on remote host
* $ make BUILD_CODE_COVERAGE=1 # build with support for collecting code coverage information
* $ make SAVE_OPT_RECORD=".*" # save compiler (linker if BUILD_LTO) optimization record, for analysis by a tool like optview

The XNU build system can optionally output color-formatted build output. To enable this, you can either
set the `XNU_LOGCOLORS` environment variable to `y`, or you can pass `LOGCOLORS=y` to the make command.

### Customize the XNU Version

The xnu version is derived from the SDK or KDK by reading the `CFBundleVersion`
of their `System/Library/Extensions/System.kext/Info.plist` file.
This can be customized by setting the `RC_DARWIN_KERNEL_VERSION` variable in
the environment or on the `make` command line.


See doc/building/xnu_version.md for more details.

### Debug Information Formats

By default, a DWARF debug information repository is created during the install phase; this is a "bundle" named kernel.development.\<variant>.dSYM
To select the older STABS debug information format (where debug information is embedded in the kernel.development.unstripped image), set the BUILD_STABS environment variable.

```sh
export BUILD_STABS=1
make
```


## Building KernelCaches

To test the xnu kernel, you need to build a kernelcache that links the kexts and
kernel together into a single bootable image.
To build a kernelcache you can use the following mechanisms:

* Using automatic kernelcache generation with `kextd`.
  The kextd daemon keeps watching for changing in `/System/Library/Extensions` directory.
  So you can setup new kernel as

    ```text
    cp BUILD/obj/DEVELOPMENT/X86_64/kernel.development /System/Library/Kernels/
    touch /System/Library/Extensions
    ps -e | grep kextd
    ```

* Manually invoking `kextcache` to build new kernelcache.

    ```text
    kextcache -q -z -a x86_64 -l -n -c /var/tmp/kernelcache.test -K /var/tmp/kernel.test /System/Library/Extensions
    ```


## Booting a KernelCache on a Target machine

### For Internal Developers

The development kernel and iBoot supports configuring boot arguments so that we can safely boot into test kernel and, if things go wrong, safely fall back to previously used kernelcache.
Following are the steps to get such a setup:

1. Create kernel cache using the kextcache command as `/kernelcache.test`
2. Copy exiting boot configurations to alternate file

    ```sh
    cp /Library/Preferences/SystemConfiguration/com.apple.Boot.plist /next_boot.plist
    ```

3. Update the kernelcache and boot-args for your setup

    ```sh
    plutil -insert "Kernel Cache" -string "kernelcache.test" /next_boot.plist
    plutil -replace "Kernel Flags" -string "debug=0x144 -v kernelsuffix=test " /next_boot.plist
    ```

4. Copy the new config to `/Library/Preferences/SystemConfiguration/`

    ```sh
    cp /next_boot.plist /Library/Preferences/SystemConfiguration/boot.plist
    ```

5. Bless the volume with new configs.

    ```text
    sudo -n bless  --mount / --setBoot --nextonly --options "config=boot"
    ```

   The `--nextonly` flag specifies that use the `boot.plist` configs only for one boot.
   So if the kernel panic's you can easily power reboot and recover back to original kernel.

### For External Developers

**SECURITY WARNING:** Installing a custom kernel requires lowering the system security settings. On Intel Macs, you must disable System Integrity Protection (SIP), set Secure Boot to "No Security," and disable the authenticated root volume. On Apple Silicon Macs, you must set the security policy to "Reduced Security" and further downgrade to "Permissive" via Recovery Mode. Failure to do this will result in a system that fails to boot.

**Note:** Building a kernel cache MUST be done on the device where you will boot the custom kernel.

**Note:** Installing a kernel could potentially render your system un-bootable, so testing in a VM is highly recommended.

#### Intel Mac: Install and Run

After building, you should have a new kernel at `{xnu}/BUILD/obj/kernel[.development]`.

##### 1. Build the Kernel Cache

```sh
cd xnu-{version}
kmutil create -a x86_64 -Z -n boot sys \
  -B BUILD/BootKernelExtensions.kc \
  -S BUILD/SystemKernelExtensions.kc \
  -k BUILD/obj/kernel \
  --elide-identifier com.apple.driver.AppleIntelTGLGraphicsFramebuffer
```

**Note:** The AppleIntelTGLGraphicsFramebuffer driver will not link against the open source XNU kernel.

##### 2. Mount a live view of the filesystem

```sh
mkdir BUILD/mnt
sudo mount -o nobrowse -t apfs /dev/diskMsN $PWD/BUILD/mnt
```

**Note:** `diskMsN` can be found by running `mount`, looking for the root mount's device, and removing the last "s" segment. For example, if root is `/dev/disk1s2s3`, mount `/dev/disk1s2`.

##### 3. Install the kernel and KCs

```sh
sudo ditto BUILD/BootKernelExtensions.kc "$PWD/BUILD/mnt/System/Library/KernelCollections/BootKernelExtensions.kc.development"
sudo ditto BUILD/SystemKernelExtensions.kc "$PWD/BUILD/mnt/System/Library/KernelCollections/SystemKernelExtensions.kc.development"
sudo ditto BUILD/obj/kernel "$PWD/BUILD/mnt/System/Library/Kernels/kernel.development"
```

**Note:** "development" can be replaced with any short string (e.g., "usr"). Using a suffix allows maintaining a fallback for system recovery.

##### 4. Bless the new KCs

```sh
sudo bless --folder $PWD/BUILD/mnt/System/Library/CoreServices \
  --bootefi --create-snapshot
```

##### 5. Set boot-args to select the new KC

```sh
sudo nvram boot-args="kcsuffix=development wlan.skywalk.enable=0"
```

**Note:** The `wlan.skywalk.enable=0` boot-arg is necessary to disable Skywalk in the WLAN driver, as Skywalk is not part of the open source kernel. If you encounter Skywalk-related panics, you may also need to add `dk=0` to disable DriverKit drivers.

##### 6. Reboot!

**Important Notes:**
* Due to missing network (Skywalk) and power management (XCPM) functionality, some features like sleep/wake will not work
* If your machine becomes un-bootable, boot into Recovery Mode (hold Option during boot, then press Cmd-R) and set `nvram boot-args="kcsuffix=release"`
* The filenames are important - the booter loads `BootKernelExtensions.kc[.suffix]`, and kernelmanagerd mmaps the corresponding `SystemKernelExtensions.kc[.suffix]`
* The boot and system KCs must be generated together (system KC links against boot KC). Mis-matched KCs will cause a panic
* For serial output during boot, add boot-args: `serial=3 -v`

#### Apple Silicon Mac: Install and Run

After building, you should have a new kernel at `{xnu}/BUILD/obj/kernel[.development].{platform}` (e.g., `kernel.development.t8101`).

##### 1. Build the Kernel Cache

```sh
cd xnu-{version}
kmutil create -a arm64e -z -V development -n boot \
  -B BUILD/OpenSource.kc \
  -k BUILD/obj/kernel.development.t8101 \
  -r /System/Library/Extensions \
  -r /System/Library/DriverExtensions \
  -x \
  $(kmutil inspect -V release --no-header \
    | grep -v "SEPHiber" | awk '{print " -b "$1; }')
```

**Notes:**
* This command uses a nested `kmutil inspect` to gather the list of drivers in your current KC
* The `grep` command filters out the SEP hibernation driver (won't link with open source kernel)
* The KC filename doesn't matter on Apple silicon (unlike Intel). Here it's called `OpenSource.kc`
* Replace `-V development` with `-V release` if you built the release kernel (keep `-V release` in the inner `kmutil inspect`)

##### 2. Boot into Recovery Mode

1. Shutdown the computer
2. Power on by clicking the power button, then **hold** the power button until you see "Loading startup options..."
3. Select "Options" and then "Continue"
4. From the "Utilities" menu, select "Terminal"

##### 3. Disable SIP and set boot-args (one-time operation)

From the Recovery mode terminal:

```sh
csrutil disable
# Follow prompts and enter your password

bputil -a
# This enables custom boot-args to be sent to the kernel
```

##### 4. Reboot to main OS and set boot-args

From the Terminal in the main OS:

```sh
sudo nvram boot-args="wlan.skywalk.enable=0 dk=0"
```

**Note:** `dk=0` disables DriverKit.

##### 5. Boot back into Recovery Mode (see step 2)

##### 6. Install the new KC

From the Recovery mode terminal:

```sh
cd /Volumes/Macintosh\ HD/path/to/xnu
# Replace "Macintosh HD" with your disk name and add the path to xnu source
# Example: cd /Volumes/Macintosh\ HD/Users/jeremy/sw/xnu-{version}

kmutil configure-boot -v /Volumes/Macintosh\ HD -c BUILD/OpenSource.kc
# Replace "Macintosh HD" with your disk name
```

##### 7. Reboot!

**Important Notes:**
* Due to missing functionality, hibernate and Rosetta (x86_64 apps) will not work
* You do not need to disable the Authenticated Root Volume to boot a custom kernel on Apple silicon
* If un-bootable, boot into Recovery Mode and upgrade Security to "Reduced Security" or "Full Security"
* Boot-args to control which kernel/KC boots do not work on Apple silicon
* Booting a new kernel/KC always requires Recovery Mode and `kmutil configure-boot`
* Security settings only need to be changed the first time you boot a custom KC
* **CAVEAT:** `kmutil configure-boot` only works on the first macOS volume. If you have multiple bootable volumes, you can only boot a custom kernel on the first installation


## Creating tags and cscope

Set up your build environment and from the top directory, run:

    make tags     # this will build ctags and etags on a case-sensitive volume, only ctags on case-insensitive
    make TAGS     # this will build etags
    make cscope   # this will build cscope database

## Installing New Header Files from XNU

XNU installs header files at the following locations -

    a. $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
    b. $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
    c. $(DSTROOT)/usr/include/
    d. $(DSTROOT)/usr/local/include/
    e. $(DSTROOT)/System/DriverKit/usr/include/
    f. $(DSTROOT)/System/Library/Frameworks/IOKit.framework/Headers
    g. $(DSTROOT)/System/Library/Frameworks/IOKit.framework/PrivateHeaders
    h. $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders

`Kernel.framework` is used by kernel extensions.\
The `System.framework`, `/usr/include` and `/usr/local/include` are used by user level applications. \
`IOKit.framework` is used by IOKit userspace clients. \
`/System/DriverKit/usr/include` is used by userspace drivers. \
The header files in framework's `PrivateHeaders` are only available for **Apple Internal Development**.

The directory containing the header file should have a Makefile that
creates the list of files that should be installed at different locations.
If you are adding the first header file in a directory, you will need to
create Makefile similar to `xnu/bsd/sys/Makefile`.

Add your header file to the correct file list depending on where you want
to install it. The default locations where the header files are installed
from each file list are -

    a. `DATAFILES` : To make header file available in user level -
       `$(DSTROOT)/usr/include`
       `$(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders`

    b. `DRIVERKIT_DATAFILES` : To make header file available to DriverKit userspace drivers -
       `$(DSTROOT)/System/DriverKit/usr/include`

    c. `PRIVATE_DATAFILES` : To make header file available to Apple internal in
       user level -
       `$(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders`

    d. `EMBEDDED_PRIVATE_DATAFILES` : To make header file available in user
       level for macOS as `EXTRA_DATAFILES`, but Apple internal in user level
       for embedded OSes as `EXTRA_PRIVATE_DATAFILES` -
       `$(DSTROOT)/usr/include` (`EXTRA_DATAFILES`)
       `$(DSTROOT)/usr/local/include` (`EXTRA_PRIVATE_DATAFILES`)

    e. `KERNELFILES` : To make header file available in kernel level -
       `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers`
       `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`

    f. `PRIVATE_KERNELFILES` : To make header file available to Apple internal
       for kernel extensions -
       `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders`

    g. `MODULEMAPFILES` : To make module map file available in user level -
       `$(DSTROOT)/usr/include`

    h. `PRIVATE_MODULEMAPFILES` : To make module map file available to Apple
       internal in user level -
       `$(DSTROOT)/usr/local/include`

    i. `LIBCXX_DATAFILES` : To make header file available to in-kernel libcxx clients:
       `$(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders/kernel_sdkroot`

    j. `EXCLAVEKIT_DATAFILES` : To make header file available to Apple internal
       ExclaveKit SDK -
       `$(DSTROOT)/System/ExclaveKit/usr/include`

    k. `EXCLAVECORE_DATAFILES` : To make header file available to Apple internal
       ExclaveCore SDK -
       `$(DSTROOT)/System/ExclaveCore/usr/include`

The Makefile combines the file lists mentioned above into different
install lists which are used by build system to install the header files. There
are two types of install lists: machine-dependent and machine-independent.
These lists are indicated by the presence of `MD` and `MI` in the build
setting, respectively. If your header is architecture-specific, then you should
use a machine-dependent install list (e.g. `INSTALL_MD_LIST`). If your header
should be installed for all architectures, then you should use a
machine-independent install list (e.g. `INSTALL_MI_LIST`).

If the install list that you are interested does not exist, create it
by adding the appropriate file lists.  The default install lists, its
member file lists and their default location are described below -

a. `INSTALL_MI_LIST`, `INSTALL_MODULEMAP_MI_LIST` : Installs header and module map
    files to a location that is available to everyone in user level.
    Locations -
        $(DSTROOT)/usr/include
    Definition -
        INSTALL_MI_LIST = ${DATAFILES}
        INSTALL_MODULEMAP_MI_LIST = ${MODULEMAPFILES}

b. `INSTALL_DRIVERKIT_MI_LIST` : Installs header file to a location that is
    available to DriverKit userspace drivers.
    Locations -
        $(DSTROOT)/System/DriverKit/usr/include
    Definition -
        INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

c.  `INSTALL_MI_LCL_LIST`, `INSTALL_MODULEMAP_MI_LCL_LIST` : Installs header and
    module map files to a location that is available for Apple internal in user level.
    Locations -
        $(DSTROOT)/usr/local/include
    Definition -
        INSTALL_MI_LCL_LIST =
        INSTALL_MODULEMAP_MI_LCL_LIST = ${PRIVATE_MODULEMAPFILES}

d. `INSTALL_IF_MI_LIST` : Installs header file to location that is available
    to everyone for IOKit userspace clients.
    Locations -
        $(DSTROOT)/System/Library/Frameworks/IOKit.framework/Headers
    Definition -
        INSTALL_IF_MI_LIST = ${DATAFILES}

e. `INSTALL_IF_MI_LCL_LIST` : Installs header file to location that is
    available to Apple internal for IOKit userspace clients.
    Locations -
        $(DSTROOT)/System/Library/Frameworks/IOKit.framework/PrivateHeaders
    Definition -
        INSTALL_IF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

f.  `INSTALL_SF_MI_LCL_LIST` : Installs header file to a location that is available
    for Apple internal in user level.
    Locations -
        $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
    Definition -
        INSTALL_SF_MI_LCL_LIST = ${DATAFILES} ${PRIVATE_DATAFILES}

g. `INSTALL_KF_MI_LIST` : Installs header file to location that is available
    to everyone for kernel extensions.
    Locations -
        $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
    Definition -
        INSTALL_KF_MI_LIST = ${KERNELFILES}

h. `INSTALL_KF_MI_LCL_LIST` : Installs header file to location that is
    available for Apple internal for kernel extensions.
    Locations -
        $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
    Definition -
        INSTALL_KF_MI_LCL_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

i. `EXPORT_MI_LIST` : Exports header file to all of xnu (bsd/, osfmk/, etc.)
    for compilation only. Does not install anything into the SDK.
    Definition -
        EXPORT_MI_LIST = ${KERNELFILES} ${PRIVATE_KERNELFILES}

j. `INSTALL_KF_LIBCXX_MI_LIST` : Installs header file for in-kernel libc++ support.
    Locations -
        $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders/kernel_sdkroot
    Definition -
        INSTALL_KF_LIBCXX_MI_LIST = ${LIBCXX_DATAFILES}

k. `INSTALL_EXCLAVEKIT_MI_LIST` : Installs header file to location that is
    available for Apple internal for ExclaveKit.
    Locations -
        $(DSTROOT)/System/ExclaveKit/usr/include
    Definition -
        INSTALL_EXCLAVEKIT_MI_LIST = ${EXCLAVEKIT_DATAFILES}

l. `INSTALL_EXCLAVECORE_MI_LIST` : Installs header file to location that is
    available for Apple internal for ExclaveCore.
    Locations -
        $(DSTROOT)/System/ExclaveCore/usr/include
    Definition -
        INSTALL_EXCLAVECORE_MI_LIST = ${EXCLAVECORE_DATAFILES}

If you want to install the header file in a sub-directory of the paths
described in (1), specify the directory name using two variables
`INSTALL_MI_DIR` and `EXPORT_MI_DIR` as follows -

```text
INSTALL_MI_DIR = dirname
EXPORT_MI_DIR = dirname
```

If you want to install the module map file in a sub-directory, specify the
directory name using the variable `INSTALL_MODULEMAP_MI_DIR` as follows -

```text
INSTALL_MODULEMAP_MI_DIR = dirname
```

A single header file can exist at different locations using the steps
mentioned above.  However it might not be desirable to make all the code
in the header file available at all the locations.  For example, you
want to export a function only to kernel level but not user level.

 You can use C language's pre-processor directive (#ifdef, #endif, #ifndef)
 to control the text generated before a header file is installed.  The kernel
 only includes the code if the conditional macro is TRUE and strips out
 code for FALSE conditions from the header file.

 Some pre-defined macros and their descriptions are -

1. `PRIVATE` : If defined, enclosed definitions are considered System
Private Interfaces. These are visible within xnu and
exposed in user/kernel headers installed within the AppleInternal
"PrivateHeaders" sections of the System and Kernel frameworks.
2. `KERNEL_PRIVATE` : If defined, enclosed code is available to all of xnu
kernel and Apple internal kernel extensions and omitted from user
headers.
3. `BSD_KERNEL_PRIVATE` : If defined, enclosed code is visible exclusively
within the xnu/bsd module.
4. `MACH_KERNEL_PRIVATE`: If defined, enclosed code is visible exclusively
within the xnu/osfmk module.
5. `XNU_KERNEL_PRIVATE`: If defined, enclosed code is visible exclusively
within xnu.
6. `KERNEL` :  If defined, enclosed code is available within xnu and kernel
    extensions and is not visible in user level header files.  Only the
    header files installed in following paths will have the code -

    ```text
    $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
    $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
    ```

7. `DRIVERKIT`: If defined, enclosed code is visible exclusively in the
DriverKit SDK headers used by userspace drivers.
8. `EXCLAVEKIT`: If defined, enclosed code is visible exclusively in the
ExclaveKit SDK headers.
9. `EXCLAVECORE`: If defined, enclosed code is visible exclusively in the
ExclaveCore SDK headers.
10. `MODULES_SUPPORTED` If defined, enclosed code is visible exclusively
in locations that support modules/Swift (i.e. not System or Kernel frameworks).

## VM header file name convention
The VM headers follow the following naming conventions:
* `*_internal.h` headers contain components of the VM subsystem only for use by VM code.
* `*_xnu.h` headers contain components of the VM subsystem only for use by other xnu code.
* `*.h` headers contain components of the VM subsystem exported to kexts.
* `vm_iokit.h` header contains components of the VM subsystem exported to the iokit subsystem.
* `vm_ubc.h` header contains components of the VM subsystem exported to the ubc subsystem.


## Module map file name convention

In the simple case, a subdirectory of `usr/include` or `usr/local/include`
can be represented by a standalone module. Where this is the case, set
`INSTALL_MODULEMAP_MI_DIR` to `INSTALL_MI_DIR` and install a `module.modulemap`
file there. `module.modulemap` is used even for private modules in
`usr/local/include`; `module.private.modulemap` is not used. Caveat: in order
to stay in the simple case, the module name needs to be exactly the same as
the directory name. If that's not possible, then the following method will
need to be applied.

`xnu` contributes to the modules defined in CoreOSModuleMaps by installing
module map files that are sourced from `usr/include/module.modulemap` and
`usr/local/include/module.modulemap`. The naming convention for the `xnu`
module map files are as follows.

a. Ideally the module map file covers an entire directory. A module map
    file covering `usr/include/a/b/c` would be named `a_b_c.modulemap`.
    `usr/local/include/a/b/c` would be `a_b_c_private.modulemap`.
b. Some headers are special and require their own module. In that case,
    the module map file would be named after the module it defines.
    A module map file defining the module `One.Two.Three` would be named
    `one_two_three.modulemap`.

## Conditional Compilation

`xnu` offers the following mechanisms for conditionally compiling code:

1. *CPU Characteristics* If the code you are guarding has specific
    characterstics that will vary only based on the CPU architecture being
    targeted, use this option. Prefer checking for features of the
    architecture (e.g. `__LP64__`, `__LITTLE_ENDIAN__`, etc.).
2. *New Features* If the code you are guarding, when taken together,
    implements a feature, you should define a new feature in `config/MASTER`
    and use the resulting `CONFIG` preprocessor token (e.g. for a feature
    named `config_virtual_memory`, check for `#if CONFIG_VIRTUAL_MEMORY`).
    This practice ensures that existing features may be brought to other
    platforms by simply changing a feature switch.
3. *Existing Features* You can use existing features if your code is
    strongly tied to them (e.g. use `SECURE_KERNEL` if your code implements
    new functionality that is exclusively relevant to the trusted kernel and
    updates the definition/understanding of what being a trusted kernel means).

It is recommended that you avoid compiling based on the target platform. `xnu`
does not define the platform macros from `TargetConditionals.h`
(`TARGET_OS_OSX`, `TARGET_OS_IOS`, etc.).


## Debugging XNU

By default, the kernel reboots in the event of a panic.
This behavior can be overriden by the `debug` boot-arg -- `debug=0x14e` will cause a panic to wait for a debugger to attach.
To boot a kernel so it can be debugged by an attached machine, override the `kdp_match_name` boot-arg with the appropriate `ifconfig` interface.
Ethernet, Thunderbolt, and serial debugging are supported, depending on the hardware.

Use LLDB to debug the kernel:

```text
xcrun -sdk macosx lldb <path-to-unstripped-kernel>
(lldb) gdb-remote [<host-ip>:]<port>
```

The debug info for the kernel (dSYM) comes with a set of macros to support kernel debugging.
To load these macros automatically when attaching to the kernel, add the following to `~/.lldbinit`:

```text
settings set target.load-script-from-symbol-file true
```

`tools/lldbmacros` contains the source for these commands.
See the README in that directory for their usage, or use the built-in LLDB help with:

```text
(lldb) help showcurrentstacks
```


## Platform to Mac Model Mappings

### T6000
* Mac13,1 Mac13,2
* MacBookPro18,1 MacBookPro18,2 MacBookPro18,3 MacBookPro18,4
* Macmini10,1

### T6020
* Mac14,5 Mac14,6 Mac14,8 Mac14,9 Mac14,10 Mac14,12 Mac14,13 Mac14,14

### T6030
* Mac15,6 Mac15,7

### T6031
* Mac15,8 Mac15,9 Mac15,10 Mac15,11 Mac15,14

### T6041
* Mac16,5 Mac16,6 Mac16,7 Mac16,8 Mac16,9 Mac16,11

### T8103
* iMac21,1 iMac21,2
* MacBookAir10,1
* MacBookPro17,1
* Macmini9,1

### T8112
* Mac14,2 Mac14,3 Mac14,7 Mac14,15

### T8122
* Mac15,3 Mac15,4 Mac15,5 Mac15,12 Mac15,13

### T8132
* Mac16,1 Mac16,2 Mac16,3 Mac16,10 Mac16,12 Mac16,13

### T8142
* Mac17,2 Mac17,3 Mac17,4
