#!/usr/bin/env python

from __future__ import absolute_import
import sys


def type_map(x):
    return "TYPE_" + x.upper()


def print_preamble():
    print(r'struct blacklist_entry blacklist[] = {')


def print_entry(kext, func, type):
    strkext = '"' + kext + '"' if kext != "" else "NULL"
    strfunc = '"' + func + '"' if func != "" else "NULL"

    strtype = "0"
    if type:
        strtype = type_map(type) if type != "" else "normal"

    print("""	{{
		.kext_name = {},
		.func_name = {},
		.type_mask = {},
	}},""".format(strkext, strfunc, strtype))


def print_postamble(nentries, extra_entries):
    print('') # add space for new entries added at runtime
    print(r'	/* Unused entries that can be populated at runtime */')

    for _ in range(extra_entries):
        print_entry("", "", None)

    print("};\n")

    print('static size_t blacklist_entries = {};'.format(nentries))
    print('static const size_t blacklist_max_entries = {};'.format(
        nentries + extra_entries))


def extract_symbol(line):
    fields = line.split(":")
    if len(fields) == 3:
        return [field.strip() for field in fields]
    raise Exception("Invalid exclusion rule: {}".format(line))


with open(sys.argv[1]) as fd:
    nentries = 0
    extra_entries = 5

    print_preamble()

    for line in fd.readlines():
        line = line.strip()
        if line and not line.startswith("#"):
            kext, func, ty = extract_symbol(line)
            print_entry(kext, func, ty)
            nentries += 1

    print_postamble(nentries, extra_entries)
