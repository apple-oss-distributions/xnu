#!/usr/bin/env python3
import sys

COLOR_RED = "\033[1;31m"
COLOR_RESET = "\033[0m"
# read a .CFLAGS file and print the appropriately quoted clang command line arguments
def main():
    in_path = sys.argv[1]
    try:
        line = open(in_path).read()
    except FileNotFoundError as e:
        print(f"{COLOR_RED}Error: {e}\nDid you forget to add a `#define UT_MODULE <module>` in your test?{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    # split by " -" (with space) to avoid issue with paths that contain dashes
    dash_split = line.split(' -')
    output = []
    # change ' -DX=y z' to ' -DX="y z"'
    for i, s in enumerate(dash_split):
        if i == 0:
            continue # skip the clang executable
        if '=' in s:
            st = s.strip()
            eq_sp = st.split('=')
            if ' ' in eq_sp[1]:
                output.append(f'-{eq_sp[0]}="{eq_sp[1]}"')
                continue

        output.append(f"-{s}")
    print(" ".join(output))


if __name__ == "__main__":
    sys.exit(main())
