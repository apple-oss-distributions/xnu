#!/usr/bin/env python3
import sys
import os
import subprocess

# This script collects coverage data from the run of all unit-tests and merges the data to a single file
# see also tests/unit/README.md
# how to use:
# > rm -rf BUILD
# > rm -rf tests/unit/build
# > make -C tests/unit SDKROOT=macosx.internal BUILD_CODE_COVERAGE=1 install
# > tests/unit/tools/run_coverage.py tests/unit/build/sym/run_unittests.targets <folder-name-to-create>

def main():
    targets_list_path = sys.argv[1]
    outdir = sys.argv[2]
    targets_list = [line.strip() for line in open(targets_list_path).readlines()]
    target_prefix = os.path.dirname(targets_list_path)
    os.makedirs(outdir, exist_ok=False)
    prof_files = []
    for t in targets_list:
        prof_file = os.path.join(outdir, "coverage__" + t.replace("/", "_") + ".profraw")
        test_path = os.path.join(target_prefix, t)
        print(f"running {test_path}")
        result = subprocess.run(f'LLVM_PROFILE_FILE="{prof_file}" {test_path}', shell=True, stdout=subprocess.DEVNULL)
        if result.returncode == 0 or result.returncode == 69:
            print("  \033[32mPASS\033[0m")
        else:
            print("  \033[31FAIL\033[0m")
        assert(os.path.exists(prof_file))
        print(f"  Got {prof_file}")
        prof_files.append(prof_file)
    print("merging...")
    merged_data = f"{outdir}/coverage_data.profdata"
    subprocess.run("xcrun -sdk macosx.internal llvm-profdata merge -sparse " + " ".join(prof_files) + f" -o {merged_data}", shell=True)
    assert(os.path.exists(merged_data))
    print(f"  Got {merged_data}")


if __name__ == "__main__":
    sys.exit(main())