#!/usr/bin/env python3

helpdoc = """
A simple utility that verifies the syntax for python scripts.
The checks it does are :
  * Check for 'tab' characters in .py files
  * Compile errors in py sources
Usage:
  python syntax_checker.py <python_source_file> [<python_source_file> ..] 
"""
import sys
import os
import re

tabs_search_rex = re.compile(r"^\s*\t+",re.MULTILINE|re.DOTALL)

def find_non_ascii(s):
    for c in s:
        if ord(c) >= 0x80: return True
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Unknown arguments", file=sys.stderr)
        print(helpdoc)
        sys.exit(1)
    for fname in sys.argv[1:]:
        if not os.path.exists(fname):
            print("Error: Cannot recognize %s as a file" % fname, file=sys.stderr)
            sys.exit(1)
        if fname.split('.')[-1] != 'py':
            print("Note: %s is not a valid python file. Skipping." % fname)
            continue
        fh = open(fname)
        strdata = fh.readlines()
        lineno = 0
        syntax_fail = False
        for linedata in strdata:
            lineno += 1
            if len(tabs_search_rex.findall(linedata)) > 0 :
                print("Error: Found a TAB character at %s:%d" % (fname, lineno), file=sys.stderr)
                syntax_fail = True
        if find_non_ascii(linedata):
            print("Error: Found a non ascii character at %s:%d" % (fname, lineno), file=sys.stderr)
            syntax_fail = True
        if syntax_fail:
            print("Error: Syntax check failed. Please fix the errors and try again.", file=sys.stderr)
            sys.exit(1)
        #now check for error in compilation
        try:
            with open(fname, 'r') as file:
                source = file.read() + '\n'
                compile_result = compile(source, fname, 'exec')
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            print("Error: Compilation failed. Please fix the errors and try again.", file=sys.stderr)
            sys.exit(1)
        print("Success: Checked %s. No syntax errors found." % fname)
    sys.exit(0)

