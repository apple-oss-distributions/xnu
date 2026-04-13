#!/usr/bin/env python3
import sys
import subprocess

# get the strings XNU build-folder strings for the given device
def main():
    sdkroot = sys.argv[1]
    target_name = sys.argv[2]  # e.g. j414c
    query = f"SELECT DISTINCT KernelMachOArchitecture, KernelPlatform, SDKPlatform FROM Targets WHERE TargetType == '{target_name}'"
    r = subprocess.check_output(["xcrun", "--sdk", sdkroot, "embedded_device_map", "-query", query], encoding="ascii")
    r = r.strip()
    if len(r) == 0:
        raise Exception(f"target not found {target_name}")
    arch, kernel_platform, sdk_platform = r.split("|")

    if arch.startswith("arm64"):  # can be arm64, arm64e
        arch = "ARM64"
    elif arch.startswith("arm"):
        arch = "ARM"
    else:
        raise Exception(f"unsupported arch {arch}")

    if sdk_platform == "macosx":
        plaform_for_config = "MacOSX"
    elif sdk_platform == "iphoneos":
        plaform_for_config = "iPhoneOS"
    elif sdk_platform == "appletvos":
        plaform_for_config = "tvOS"
    elif sdk_platform == "watchos":
        plaform_for_config = "WatchOS"
    elif sdk_platform == "xros":
        plaform_for_config = "XROS"
    else:
        plaform_for_config = "unexpected"

    print(arch + " " + kernel_platform + " " + plaform_for_config)

if __name__ == "__main__":
    sys.exit(main())
