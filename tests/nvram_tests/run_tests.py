import subprocess
import shutil
import os
import argparse
import sys

# python3 tests/nvram_tests/run_tests.py -h

test_files = []
# tests that require extra command line arguments(example: nvram reset is called only if -r is passed)
special_calls = {
    "nvram_nonentitled": [
        "nvram_nonentitled -n xnu.nvram.TestImmutable -- -r",
        "nvram_nonentitled -n xnu.nvram.TestResetOnlyDel -- -r",
        "nvram_nonentitled -n xnu.nvram.TestEntRst -- -r",
        "nvram_nonentitled -n xnu.nvram.TestEntDel -- -r",
        "nvram_nonentitled -n xnu.nvram.TestNVRAMReset -- -r",
        "nvram_nonentitled -n xnu.nvram.TestNVRAMOblit -- -r",
    ],
    "nvram_system": [
        "nvram_system -n xnu.nvram.TestEntRstSys -- -r",
        "nvram_system -n xnu.nvram.TestNVRAMResetSys -- -r",
        "nvram_system -n xnu.nvram.TestNVRAMOblitSys -- -r",
    ],
    "nvram_ve_reset": ["nvram_ve_reset -n xnu.nvram.TestEntRstEnt -- -r"],
    "nvram_ve_mod": [
        "nvram_ve_mod -n xnu.nvram.TestEntModRstEnt -- -r",
        "nvram_ve_mod -n xnu.nvram.TestEntModRstSysEnt -- -r",
    ],
}


def create_arg_parser():
    example_cmd = '''examples:
    To use default args:
        python %(prog)s
    To use iphoneos sdk:
        python %(prog)s -s 1
    To build only:
        python %(prog)s -br 0 -f <path to test files if not default>
    To run only:
        python %(prog)s -br 1 -b <path to build files if not default>
    To run only:
    To invoke reset calls:
        python %(prog)s -r 1'''

    parser = argparse.ArgumentParser(
        description='Builds and/or runs nvram tests for xnu',
        epilog=example_cmd,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    default_build_path = "tests/build/sym/"
    default_files_path = "tests/nvram_tests"

    parser.add_argument('-br', type=int, default=2, choices=[
                        0, 1, 2], required=False, help='0=only builds, 1=only runs, 2=builds and runs')
    parser.add_argument('-b', type=str, default=default_build_path,
                        required=False, help='Path to the build files')
    parser.add_argument('-f', type=str, default=default_files_path,
                        required=False, help='Path to the test files')
    parser.add_argument('-r', type=int, default=0, choices=[
                        0, 1], required=False, help='0=ignores the reset calls, 1=uses the reset calls')
    parser.add_argument('-s', type=int, default=0, choices=[
                        0, 1], required=False, help='0=macos sdk, 1=iphoneos sdk')

    return parser


def run_tests(build_path, test_arg):
    args = "sudo ./" + build_path + test_arg
    output = subprocess.getoutput(args)
    print(output)


if __name__ == "__main__":

    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(sys.argv[1:])
    build_path = parsed_args.b
    file_path = parsed_args.f
    reset_flag = parsed_args.r
    action = parsed_args.br
    sdk = "macosx.internal" if (parsed_args.s == 0) else "iphoneos.internal"

    print(parsed_args)

    if (action != 1):
        if not os.path.exists(file_path) or os.path.basename(os.getcwd()) != 'xnu':
            print("Invalid file path:", file_path)
            sys.exit()

        # Iterate through test_files_path and get all the test files to run
        for file in os.listdir(file_path):
            if file.endswith(".c") and "helper" not in file:
                test_files.append(file.rsplit(".", maxsplit=1)[0])

        # Delete existing build folder
        if os.path.isdir(build_path):
            shutil.rmtree(build_path)

        # Build the tests
        for i in test_files:
            print("\n\n************************************** Building",
                  i, "**************************************\n\n")
            args = "xcrun -sdk " + sdk + " make -C tests " + i
            output = subprocess.getoutput(args)
            print(output)

    if (action != 0):
        if (action == 1):
            for file in os.listdir(build_path):
                if not file.endswith(".dSYM"):
                    test_files.append(file)
        # Run the tests
        for i in test_files:
            print("\n\n************************************** Testing",
                  i, "**************************************\n\n")

            if (reset_flag == 1) and (i in special_calls.keys()):
                for j in special_calls[i]:
                    run_tests(build_path, j)
            run_tests(build_path, i)
