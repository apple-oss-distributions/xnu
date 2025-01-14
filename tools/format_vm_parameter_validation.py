#!/usr/bin/python3

# format_vm_parameter_validation.py
# Pretty-print the output of tests/vm/vm_parameter_validation.c
#
# usage:
#     vm_parameter_validation | format_vm_parameter_validation.py

import re
import sys
import copy
import itertools

# magic return values used for in-band signalling
# fixme duplicated in vm_parameter_validation.c
# fixme also duplicated in other_return_values below
RESULT_SUCCESS  = 0
RESULT_BUSTED   = -99
RESULT_IGNORED  = -98
RESULT_ZEROSIZE = -97
RESULT_PANIC    = -96
RESULT_GUARD    = -95
RESULT_MISMATCH = -94
RESULT_OUT_PARAM_BAD = -93
# Some Mach errors use their normal integer values, 
# but we handle them specially here because those
# integers are too long to fit in the grid output.
RESULT_MACH_SEND_INVALID_MEMORY = 0x1000000c
RESULT_MACH_SEND_INVALID_DEST = 0x10000003

# output formatting
format_result = {
    RESULT_SUCCESS       : '  .',
    RESULT_BUSTED        : ' **',
    RESULT_MISMATCH      : ' ##',
    RESULT_IGNORED       : '   ',
    RESULT_ZEROSIZE      : '  o',
    RESULT_PANIC         : ' pp',
    RESULT_GUARD         : ' gg',
    RESULT_OUT_PARAM_BAD : ' ot',
    RESULT_MACH_SEND_INVALID_MEMORY : ' mi',
    RESULT_MACH_SEND_INVALID_DEST :   ' md',
}

# same as format_result, but for functions 
# where 0=failure and 1=success
format_bool_result = format_result.copy()
format_bool_result.update({
    0 : '  x',
    1 : format_result[RESULT_SUCCESS],
})

def formatter_for_testname(testname):
    if (error_code_values_for_testname(testname) == bool_return_values):
        return format_bool_result
    return format_result

format_default = '%3d'
format_col_width = 3
format_empty_col = format_col_width * ' '
format_indent_width = 4
format_indent = format_indent_width * ' '


# record the result of one trial:
# ret: the return value from the tested function
# parameters: array of the input parameter names for that trial
#   (for example ["start PGSZ-2", "size -1"])
class Result:
    def __init__(self, new_ret, new_parameters):
        self.ret = new_ret
        self.parameters = new_parameters
    def __repr__(self):
        return str(self.ret) + " = " + str(self.parameters)

# record the results of all trials in one test
# testname: the name of the test (including the function being tested)
# config: a string describing OS, CPU, etc
# compat: code for error compatibility
# results: an array of Result, one per trial
class Test:
    def __init__(self, new_name, new_config, new_compat, new_results = []):
        self.testname = new_name
        self.config = new_config
        self.compat = new_compat
        self.results = new_results

# print column labels under some output
# example output given indent=2 col_width=4 labels=[foo,bar,baz,qux]:
#  |   |   |   |
#  |   |   |   qux
#  |   |   baz
#  |   bar
#  foo
def print_column_labels(labels, indent_width, col_width):
    indent = indent_width * ' '
    empty_column = '|' + (col_width-1) * ' '

    unprinted = len(labels)
    print(indent + unprinted*empty_column)

    for label in reversed(labels):
        unprinted -= 1
        print(indent + unprinted*empty_column + label)

# pretty-print one function return code
def print_one_result(ret, formatter):
    if ret in formatter:
        print(formatter[ret], end='')
    else:
        print(format_default % (ret), end='')

# choose the appropriate error code table for a test
# (either errno_return_values, bool_return_values, or kern_return_values)
def error_code_values_for_testname(testname):
    errno_fns = ['mprotect', 'msync', 'minherit', 'mincore', 'mlock', 'munlock',
                 'mmap', 'munmap', 'mremap_encrypted', 'vslock', 'vsunlock',
                 'madvise']
    bool_fns = ['useracc', 'task_find_region_details']
    for fn in errno_fns:
        if testname.startswith(fn):
            return errno_return_values
    for fn in bool_fns:
        if testname.startswith(fn):
            return bool_return_values
    return kern_return_values

# print a helpful description of the return values seen in results
# fixme these won't include RESULT_MISMATCH
def print_legend(test):
    # find all error codes represented in the results
    codes = {}
    for result in test.results:
        codes[result.ret] = True

    known_return_values = error_code_values_for_testname(test.testname)

    # print the names of the detected error codes
    output = []
    for code in sorted(codes.keys()):
        if code in known_return_values:
            output.append(known_return_values[code])
        elif code in other_return_values:
            output.append(other_return_values[code])
        elif code != 0:
            output.append(str(code) + ': ????')

    print(format_indent + '(' + ', '.join(output) + ')')

# display names for error codes returned in errno
errno_return_values = {
    1: 'EPERM',
    9: 'EBADF',
    12: 'ENOMEM',
    13: 'EACCES',
    14: 'EFAULT',
    22: 'EINVAL',
    45: 'ENOTSUP',
}
for k, v in errno_return_values.items():
    errno_return_values[k] = str(k) + ': ' + v

# display names for error codes returned in kern_return_t
kern_return_values = {
    1: 'KERN_INVALID_ADDRESS',
    2: 'KERN_PROTECTION_FAILURE',
    3: 'KERN_NO_SPACE',
    4: 'KERN_INVALID_ARGUMENT',
    5: 'KERN_FAILURE',
    6: 'KERN_RESOURCE_SHORTAGE',
    7: 'KERN_NOT_RECEIVER',
    8: 'KERN_NO_ACCESS',
    9: 'KERN_MEMORY_FAILURE',
    10: 'KERN_MEMORY_ERROR',
    11: 'KERN_ALREADY_IN_SET',
    12: 'KERN_NOT_IN_SET',
    13: 'KERN_NAME_EXISTS',
    14: 'KERN_ABORTED',
    15: 'KERN_INVALID_NAME',
    16: 'KERN_INVALID_TASK',
    17: 'KERN_INVALID_RIGHT',
    18: 'KERN_INVALID_VALUE',
    19: 'KERN_UREFS_OVERFLOW',
    20: 'KERN_INVALID_CAPABILITY',
    21: 'KERN_RIGHT_EXISTS',
    22: 'KERN_INVALID_HOST',
    23: 'KERN_MEMORY_PRESENT',
    24: 'KERN_MEMORY_DATA_MOVED',
    25: 'KERN_MEMORY_RESTART_COPY',
    26: 'KERN_INVALID_PROCESSOR_SET',
    27: 'KERN_POLICY_LIMIT',
    28: 'KERN_INVALID_POLICY',
    29: 'KERN_INVALID_OBJECT',
    30: 'KERN_ALREADY_WAITING',
    31: 'KERN_DEFAULT_SET',
    32: 'KERN_EXCEPTION_PROTECTED',
    33: 'KERN_INVALID_LEDGER',
    34: 'KERN_INVALID_MEMORY_CONTROL',
    35: 'KERN_INVALID_SECURITY',
    36: 'KERN_NOT_DEPRESSED',
    37: 'KERN_TERMINATED',
    38: 'KERN_LOCK_SET_DESTROYED',
    39: 'KERN_LOCK_UNSTABLE',
    40: 'KERN_LOCK_OWNED',
    41: 'KERN_LOCK_OWNED_SELF',
    42: 'KERN_SEMAPHORE_DESTROYED',
    43: 'KERN_RPC_SERVER_TERMINATED',
    44: 'KERN_RPC_TERMINATE_ORPHAN',
    45: 'KERN_RPC_CONTINUE_ORPHAN',
    46: 'KERN_NOT_SUPPORTED',
    47: 'KERN_NODE_DOWN',
    48: 'KERN_NOT_WAITING',
    49: 'KERN_OPERATION_TIMED_OUT',
    50: 'KERN_CODESIGN_ERROR',
    51: 'KERN_POLICY_STATIC',
    52: 'KERN_INSUFFICIENT_BUFFER_SIZE',
    53: 'KERN_DENIED',
    54: 'KERN_MISSING_KC',
    55: 'KERN_INVALID_KC',
    56: 'KERN_NOT_FOUND',
    100: 'KERN_RETURN_MAX',
    -304: 'MIG_BAD_ARGUMENTS (server type check failure)',
    # MACH_SEND_INVALID_MEMORY and other Mach errors with large integer values
    # are not handled here. They use format_result and other_return_values instead.
}
for k, v in kern_return_values.items():
    kern_return_values[k] = str(k) + ': ' + v

# display names for error codes return by a boolean function
# where 0=failure and 1=success
bool_return_values = {
    0: format_bool_result[0].lstrip() + ': false/failure',
    1: format_bool_result[1].lstrip() + ': true/success',
}

# display names for the special return values used by the test machinery
other_return_values = {
    RESULT_BUSTED:   format_result[RESULT_BUSTED].lstrip() + ': trial broken, not performed',
    RESULT_IGNORED:  '<empty> trial ignored, not performed',
    RESULT_ZEROSIZE: format_result[RESULT_ZEROSIZE].lstrip() + ': size == 0',
    RESULT_PANIC:    format_result[RESULT_PANIC].lstrip() + ': trial is believed to panic, not performed',
    RESULT_GUARD:    format_result[RESULT_GUARD].lstrip() + ': trial is believed to throw EXC_GUARD, not performed',
    RESULT_OUT_PARAM_BAD: format_result[RESULT_OUT_PARAM_BAD].lstrip() + ': trial set incorrect values to out parameters',
    RESULT_MACH_SEND_INVALID_MEMORY: format_result[RESULT_MACH_SEND_INVALID_MEMORY].lstrip() + ': MACH_SEND_INVALID_MEMORY',
    RESULT_MACH_SEND_INVALID_DEST:   format_result[RESULT_MACH_SEND_INVALID_DEST].lstrip() + ': MACH_SEND_INVALID_DEST',
}

# inside line, replace 'return 123' with 'return ERR_CODE_NAME'
def replace_error_code_return(test, line):
    known_return_values = error_code_values_for_testname(test.testname)
    for code, name in known_return_values.items():
        line = line.replace('return ' + str(code) + ';', 'return ' + name + ';')
    return line

def dimensions(results):
    if len(results) == 0:
        return 0
    return len(results[0].parameters)

# given one k-dimensional results
# return a list of k counts that is the size of each dimension
def count_each_dimension(results):
    if len(results) == 0:
        return []
    first = results[0].parameters
    k = dimensions(results)
    counts = []
    step = 1
    for dim in range(k-1, -1, -1):
        count = round(len(results) / step)
        for i in range(0, len(results), step):
            cur = results[i].parameters
            if i != 0 and cur[dim] == first[dim]:
                count = round(i / step)
                break;
        step *= count
        counts.append(count)

    counts.reverse()
    return counts;

# Reduce one k-dimensional results to many (k-1) dimensional results
# Yields a sequence of [results, name] pairs
# where results has k-1 dimensions
# and name is the parameter name from the removed dimension
def iterate_dimension(results, dim = 0):
    if len(results) == 0:
        return

    k = dimensions(results)
    dim_counts = count_each_dimension(results)

    inner_count = 1
    for d in range(dim+1, k):
        inner_count *= dim_counts[d]

    outer_step = len(results)
    for d in range(0, dim):
        outer_step = int(outer_step / dim_counts[d])

    for r in range(dim_counts[dim]):
        start = r * inner_count
        name = results[start].parameters[dim]
        new_results = []
        for i in range(start, len(results), outer_step):
            for j in range(inner_count):
                new_result = copy.deepcopy(results[i+j])
                del new_result.parameters[dim]
                new_results.append(new_result)
        yield [new_results, name]

# Print the results of a test that has two parameters (for example a test of start/size)
# If overrides!=None, use any non-SUCCESS return values from override in place of the other results.
def print_results_2D(results, formatter, overrides=None):
    # complain if results and override have different dimensions
    if overrides:
        if len(overrides) != len(results):
            print("WARNING: override results have a different height; overrides ignored")
        for i, result in enumerate(results):
            if len(overrides[i].parameters) != len(result.parameters):
                print("WARNING: override results have a different width; overrides ignored")

    columns = []
    prev_row_label = ''
    first_row_label = ''
    for i, result in enumerate(results):
        if overrides: override = overrides[i].ret

        if first_row_label == '':
            # record first row's name so we can use it to find columns
            # (assumes every row has the same column labels)
            first_row_label = result.parameters[0]

        if result.parameters[0] == first_row_label:
            # record column names in the first row
            columns.append(result.parameters[1])

        if result.parameters[0] != prev_row_label:
            # new row
            if prev_row_label != '': print(format_indent + prev_row_label)
            print(format_indent, end='')
            prev_row_label = result.parameters[0]

        if overrides and override != RESULT_SUCCESS:
            print_one_result(override, formatter)
        else:
            print_one_result(result.ret, formatter)

    if prev_row_label: print(format_indent + prev_row_label)
    print_column_labels(columns, format_indent_width + format_col_width - 1, format_col_width)

def print_results_2D_try_condensed(results, formatter):
    if 0 == len(results):
        return
    singleton = results[0].ret
    if any([result.ret != singleton for result in results]):
        print_results_2D(results, formatter)
        return
    # will print as condensed
    rows = set()
    cols = set()
    for result in results:
        rows.add(result.parameters[0].split()[1])
        cols.add(result.parameters[1].split()[1])
    print_one_result(result.ret, formatter)
    print(" for all pairs")

def print_results_3D(results, formatter, testname):
    # foreach parameter[1], print 2D table of parameter[0] and parameter[2]
    for results2D, name in iterate_dimension(results, 1):
        print(testname + ': ' + name)
        print_results_2D(results2D, formatter)

    # foreach parameter[0], print 2D table of parameter[1] and parameter[2]
    # This is redundant but can be useful for human readers.
    for results2D, name in iterate_dimension(results, 0):
        print(testname + ': ' + name)
        print_results_2D(results2D, formatter)

def print_results_4D(results, formatter):
    x, y, z = '', '', ''
    # Make a map[{3rd_param, 4th_param, ...}] = {all options}
    # For now, we print 2d tables of 1st, 2nd param for each possible combination of remaining values

    map_of_results = {}
    for _, result in enumerate(results):
        k = tuple(result.parameters[2:])

        if k not in map_of_results:
            map_of_results[k] = [result]
        else:
            map_of_results[k].append(result)

    # prepare to iterate
    prev_matrix = []
    iterable = []
    for k, result_list in map_of_results.items():
        one_2d_result = []
        matrix = []
        for result in result_list:
            x = result.parameters[0]
            y = result.parameters[1]
            repl_result = Result(result.ret, (x, y))
            one_2d_result.append(repl_result)
            matrix.append(result.ret)
        if matrix == prev_matrix:
            # if the return codes are the same everywhere, we will print successive tables only once
            # note that this assumes that the sets of 2D labels are the same everywhere, and doesn't check that assumption
            iterable[-1][0].append(k)
        else:
            iterable.append(([k], one_2d_result))
        prev_matrix = matrix

    # print
    for iter in iterable:
        print(iter[0])
        print_results_2D_try_condensed(iter[1], formatter)


# Print the results of a test that has two parameters
# (for example a test of addr only, or size only)
# If overrides!=None, use any non-SUCCESS return values from override in place of the other results.
def print_results_1D(results, formatter, overrides=None):
    # complain if results and overrides have different dimensions
    if overrides:
        if len(overrides) != len(results):
            print("WARNING: override results have a different height; overrides ignored")
        for i, result in enumerate(results):
            if len(overrides[i].parameters) != len(result.parameters):
                print("WARNING: override results have a different width; overrides ignored")

    for i, result in enumerate(results):
        if overrides: override = overrides[i].ret

        # indent, value, indent, label
        print(format_indent, end='')
        if overrides and override != RESULT_SUCCESS:
            print_one_result(override, formatter)
        else:
            print_one_result(result.ret, formatter)
        print(format_indent + result.parameters[0])

def print_results_nD(results, testname, overrides=None):
    formatter = formatter_for_testname(testname)
    
    if (dimensions(results) == 1):
        print_results_1D(results, formatter, overrides)
    elif (dimensions(results) == 2):
        print_results_2D(results, formatter, overrides)
    elif dimensions(results) == 3:
        print_results_3D(results, formatter, testname)
    elif dimensions(results) == 4:
        print_results_4D(results, formatter)
    else:
        print(format_indent + 'too many dimensions')


def main():
    data = sys.stdin.readlines()


    # remove any lines that don't start with "TESTNAME" or "TESTCONFIG" or "RESULT"
    # (including darwintest output like "PASS" or "FAIL")
    # and print them now
    # Also verify that the counts of "TEST BEGIN" == "TEST END"
    # (they will mismatch if a test suite crashed)
    testbegincount = 0
    testendcount = 0
    testlines = []
    for line in data:
        unmodified_line = line
        # count TEST BEGIN and TEST END
        if ('TEST BEGIN' in line):
            testbegincount += 1
        if ('TEST END' in line):
            testendcount += 1
        # remove any T_LOG() timestamp prefixes and KTEST prefixes
        line = re.sub('^\s*\d+:\d+:\d+ ', '', line)
        line = re.sub('^\[KTEST\]\s+[A-Z]+\s+\d+\s+(\d+\s+)?\S+\s+\d+\s+', '', line)
        line = line.lstrip()

        if (line.startswith('TESTNAME') or line.startswith('RESULT')
            or line.startswith('TESTCONFIG') or line.startswith('TESTCOMPAT')):
            testlines.append(line)  # line is test output
        elif line == '':
            pass # ignore empty lines
        else:
            print(unmodified_line, end='')  # line is other output

    # parse test output into Test and Result objects

    testnum = 0
    def group_by_test(line):
        nonlocal testnum
        if line.startswith('TESTNAME '):
            testnum = testnum+1
        return testnum

    tests = []
    for _, group in itertools.groupby(testlines, group_by_test):
        lines = list(group)

        name = lines.pop(0).removeprefix('TESTNAME ').rstrip()
        config = lines.pop(0).removeprefix('TESTCONFIG ').rstrip()
        compat = []
        results = []
        for line in lines:
            if line.startswith('RESULT'):
                components = line.removeprefix('RESULT ').rstrip().split(', ')
                ret = int(components.pop(0))
                results.append(Result(ret, components))

        tests.append(Test(name, config, compat, results))

    print('found %d tests' % (len(tests)))

    # stats to print at the end
    test_count = len(tests)
    all_configurations = set()

    # print test output
    for test in tests:
        # print test name and test config on separate lines
        # `diff` handles this better than putting both on the same line
        print('test ' + test.testname)

        print(format_indent + 'config ' + test.config)
        all_configurations.add(test.config)

        if len(test.results) == 0:
            print(format_indent + 'no results')
        else:
            print_legend(test)
            print_results_nD(test.results, test.testname)


        print('end  ' + test.testname)

    print()
    print(str(test_count) + ' test(s) performed')

    if (testbegincount != testendcount):
        print('### error: %d TEST BEGINs, %d TEST ENDs - some tests may have crashed'
              % (testbegincount, testendcount))

    print(str(len(all_configurations)) + ' configuration(s) tested:')
    for config in sorted(all_configurations):
        print(format_indent + '[' + config + ']')


main()
