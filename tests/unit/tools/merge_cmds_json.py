#!/usr/bin/env python3
import sys
import os
import glob

def main():
    xnu_root = sys.argv[1]
    xnu_build_dir = sys.argv[2]
    tests_obj_dir = sys.argv[3]

    xnu_json = os.path.join(xnu_build_dir, "compile_commands.json")
    if not os.path.exists(xnu_json):
        print(f"did not find xnu build json: {xnu_json}")
        return 0
    root_json = os.path.join(xnu_root, "compile_commands.json")

    if os.path.exists(root_json):
        if not os.path.islink(root_json):
            print(f"root json is not a symlink, not removing it: {root_json}")
            return 0

    add_text = ""
    for filename in glob.glob(os.path.join(tests_obj_dir, "*.json")):
        if filename.endswith("compile_commands.json"):
            continue
        print(f"found {filename}")
        text = open(filename).read()
        add_text += text
    add_text = add_text.rstrip()
    if add_text[-1] == ',':
        add_text = add_text[:-1]

    if len(add_text) == 0:
        print(f"did not find any json files in {tests_obj_dir}")
        return 0

    xnu_j = open(xnu_json).read()
    if xnu_j[-3:] != "\n]\n":
        print(f"doesn't look like a legit compile_commands.json: {xnu_json}")
        return 0

    xnu_j_mod = xnu_j[:-3] + ",\n\n" + add_text + "]\n"

    tests_json = os.path.join(tests_obj_dir, "compile_commands.json")
    open(tests_json, "w").write(xnu_j_mod)
    print(f"saved {tests_json}")

    if os.path.lexists(root_json):
        print(f"removing old link {root_json}")
        os.unlink(root_json)
    os.symlink(tests_json, root_json)
    print(f"added link {root_json}")


if __name__ == "__main__":
    sys.exit(main())