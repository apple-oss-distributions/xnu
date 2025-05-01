import sys, os, re, time, getopt, shlex, inspect, xnudefines
import lldb
import uuid
import base64
import json
from importlib import reload
from importlib.util import find_spec
from functools import wraps
from ctypes import c_ulonglong as uint64_t
from ctypes import c_void_p as voidptr_t
import core
from core import caching
from core.standard import *
from core.configuration import *
from core.kernelcore import *
from utils import *
from core.lazytarget import *

MODULE_NAME=__name__

""" Kernel Debugging macros for lldb.
    Please make sure you read the README COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""

COMMON_HELP_STRING = """
    -h  Show the help string for the command.
    -c [always|auto|never|0|1]
                            Control the colorized output of certain commands
    -o <path/to/filename>   The output of this command execution will be saved to file. Parser information or errors will
                            not be sent to file though. eg /tmp/output.txt
    -s <filter_string>      The "filter_string" param is parsed to python regex expression and each line of output
                            will be printed/saved only if it matches the expression.
    -v [-v...]  Each additional -v will increase the verbosity of the command.
    -p <plugin_name>        Send the output of the command to plugin. Please see README for usage of plugins.
"""
# End Utility functions
# Debugging specific utility functions

#decorators. Not to be called directly.

def static_var(var_name, initial_value):
    def _set_var(obj):
        setattr(obj, var_name, initial_value)
        return obj
    return _set_var

def header(initial_value):
    def _set_header(obj):
        setattr(obj, 'header', initial_value)
        return obj
    return _set_header

def md_header(fmt, args):
    def _set_md_header(obj):
        header = "|" + "|".join(fmt.split(" ")).format(*args) + "|"
        
        colhead = map(lambda fmt, col: "-"*len(fmt.format(col)), fmt.split(" "), args)
        sub_header = "|" + "|".join(colhead) + "|"
        setattr(obj, 'markdown', "\n".join([header, sub_header]))
        return obj
    return _set_md_header

# holds type declarations done by xnu.
#DONOTTOUCHME: Exclusive use of lldb_type_summary only.
lldb_summary_definitions = {}
def lldb_type_summary(types_list):
    """ A function decorator to register a summary for a type in lldb.
        params: types_list - [] an array of types that you wish to register a summary callback function. (ex. ['task *', 'task_t'])
        returns: Nothing. This is a decorator.
    """
    def _get_summary(obj):
        summary_function_name = "LLDBSummary" + obj.__name__

        def _internal_summary_function(lldbval, internal_dict):
            args, _, _, _ = inspect.getargspec(obj)
            if 'O' in args:
                stream = CommandOutput(summary_function_name, fhandle=sys.stdout)
                with RedirectStdStreams(stdout=stream), caching.ImplicitContext(lldbval):
                    return '\n' + obj.header + '\n' + obj(core.value(lldbval), O=stream)

            out_string = ""
            if internal_dict != None and len(obj.header) > 0 :
                out_string += "\n" + obj.header +"\n"
            with caching.ImplicitContext(lldbval):
                out_string += obj(core.value(lldbval))
            return out_string

        myglobals = globals()
        myglobals[summary_function_name] = _internal_summary_function
        summary_function = myglobals[summary_function_name]
        summary_function.__doc__ = obj.__doc__

        global lldb_summary_definitions
        for single_type in types_list:
            if config['showTypeSummary']:
                if single_type in lldb_summary_definitions:
                    lldb.debugger.HandleCommand("type summary delete --category kernel \""+ single_type + "\"")
                lldb.debugger.HandleCommand("type summary add \""+ single_type +"\" --category kernel --python-function " + MODULE_NAME + "." + summary_function_name)
            lldb_summary_definitions[single_type] = obj

        return obj
    return _get_summary

#
# Exception handling from commands
#

_LLDB_WARNING = (
    "*********************  LLDB found an exception  *********************\n"
    "{lldb_version}\n\n"
    "  There has been an uncaught exception.\n"
    "  It could be because the debugger was disconnected.\n"
    "\n"
    "  In order to debug the macro being run, run the macro again\n"
    "  with the `--debug` flag to get richer information, for example:\n"
    "\n"
    "      (lldb) showtask --debug 0x1234\n"
    "\n"
    "  In order to file a bug report instead, run the macro again\n"
    "  with the `--radar` flag which will produce a tarball to\n"
    "  attach to your report, for example:\n"
    "\n"
    "      (lldb) showtask --radar 0x1234\n"
    "********************************************************************\n"
)

def _format_exc(exc, vt):
    import traceback, textwrap

    out_str = ""

    w = textwrap.TextWrapper(width=100, placeholder="...", max_lines=3)
    tb = traceback.TracebackException.from_exception(exc, limit=None, lookup_lines=True, capture_locals=True)

    for frame in tb.stack:
        out_str += (
            f"File \"{vt.DarkBlue}{frame.filename}\"{vt.Magenta}@{frame.lineno}{vt.Reset} "
            f"in {vt.Bold}{vt.DarkCyan}{frame.name}{vt.Reset}\n"
        )
        out_str += "  Locals:\n"
        for name, value in frame.locals.items():
            variable = f"    {vt.Bold}{vt.DarkGreen}{name}{vt.Reset} = "
            first = True
            for wline in w.wrap(str(value)):
                if first:
                    out_str += variable + f"{vt.Oblique}{wline}\n"
                    first = False
                else:
                    out_str += " " * (len(name) + 7) + wline + "\n"
                out_str += vt.EndOblique

        out_str += "  " + "-" * 100 + "\n"
        try:
            src = open(frame.filename, "r")
        except IOError:
            out_str += "    < Sources not available >\n"
        else:
            with src:
                lines = src.readlines()

                startline = frame.lineno - 3 if frame.lineno > 2 else 0
                endline = min(frame.lineno + 2, len(lines))
                for lineno in range(startline, endline):

                    if lineno + 1 == frame.lineno:
                        fmt = vt.Bold + vt.Default
                        marker = '>'
                    else:
                        fmt = vt.Default
                        marker = ' '

                    out_str += f"{fmt}  {marker} {lineno + 1:5}  {lines[lineno].rstrip()}{vt.Reset}\n"

        out_str += "  " + "-" * 100 + "\n"
        out_str += "\n"

    return out_str

_RADAR_URL = "rdar://new/problem?title=LLDB%20macro%20failed%3A%20{}&attachments={}"

def diagnostic_report(result, exc, stream, cmd_name, debug_opts, lldb_log_fname=None):
    """ Collect diagnostic report for radar submission.

        @param exc (Exception type)
            Exception being reported.

        @param stream (OutputObject)
            Command's output stream to support formattting.

        @param cmd_name (str)
            Name of command being executed.

        @param debug_opts ([str])
            List of active debugging options (--debug, --radar, --pdb)

        @param lldb_log_fname (str)
            LLDB log file name to collect (optional)
    """

    # Print prologue common to all exceptions handling modes.
    print(stream.VT.DarkRed + _LLDB_WARNING.format(lldb_version=lldb.SBDebugger.GetVersionString()))
    print(stream.VT.Bold + stream.VT.DarkGreen + type(exc).__name__ +
          stream.VT.Default + ": {}".format(str(exc)) + stream.VT.Reset)
    print()

    if not debug_opts:
        result.SetError(f"{type(exc).__name__}: {exc}")
        raise exc

    #
    # Display enhanced diagnostics when requested.
    #
    if "--debug" in debug_opts:
        # Format exception for terminal
        print(_format_exc(exc, stream.VT))

        print("version:")
        print(lldb.SBDebugger.GetVersionString())
        print()

    #
    # Construct tar bundle for radar attachement
    #
    if "--radar" in debug_opts:
        import tarfile, urllib.parse
        print("Creating radar bundle ...")

        itime = int(time.time())
        tar_fname = "/tmp/debug.{:d}.tar".format(itime)

        with tarfile.open(tar_fname, "w") as tar:
            # Collect LLDB log. It can't be unlinked here because it is still used
            # for the whole duration of xnudebug debug enable.
            if lldb_log_fname is not None:
                print("  Adding {}".format(lldb_log_fname))
                tar.add(lldb_log_fname, "radar/lldb.log")
                os.unlink(lldb_log_fname)

            # Collect traceback
            tb_fname = "/tmp/tb.{:d}.log".format(itime)
            print("  Adding {}".format(tb_fname))
            with open(tb_fname,"w") as f:
                f.write(f"{type(exc).__name__}: {str(exc)}\n\n")
                f.write(_format_exc(exc, NOVT()))
                f.write("version:\n")
                f.write(f"{lldb.SBDebugger.GetVersionString()}\n")
                f.write("loaded images:\n")
                f.write(lldb_run_command("image list") + "\n")
                f.write("lldb settings:\n")
                f.write(lldb_run_command("settings show") + "\n")
            tar.add(tb_fname, "radar/traceback.log")
            os.unlink(tb_fname)

        # Radar submission
        print()
        print(stream.VT.DarkRed + "Please attach {} to your radar or open the URL below to create one:".format(tar_fname) + stream.VT.Reset)
        print()
        print("  " + _RADAR_URL.format(urllib.parse.quote(cmd_name),urllib.parse.quote(tar_fname)))
        print()
        print("Don't forget to mention where the coredump came from (e.g. original Radar ID), or attach it :)")
        print()

    # Enter pdb when requested.
    if "--pdb" in debug_opts:
        print("Starting debugger ...")
        import pdb
        pdb.post_mortem(exc.__traceback__)

    return False

#global cache of documentation for lldb commands exported by this module
#DONOTTOUCHME: Exclusive use of lldb_command only.
lldb_command_documentation = {}

_DEBUG_OPTS = { "--debug", "--radar", "--pdb" }

def lldb_command(cmd_name, option_string = '', fancy=False):
    """ A function decorator to define a command with name 'cmd_name' in the lldb scope to call python function.
        params: cmd_name - str : name of command to be set in lldb prompt.
            option_string - str: getopt like option string. Only CAPITAL LETTER options allowed.
                                 see README on Customizing command options.
            fancy - bool       : whether the command will receive an 'O' object to do fancy output (tables, indent, color)
    """
    if option_string != option_string.upper():
        raise RuntimeError("Cannot setup command with lowercase option args. %s" % option_string)

    def _cmd(obj):
        def _internal_command_function(debugger, command, exe_ctx, result, internal_dict):
            global config, lldb_run_command_state
            stream = CommandOutput(cmd_name, result)
            # need to avoid printing on stdout if called from lldb_run_command.
            if 'active' in lldb_run_command_state and lldb_run_command_state['active']:
                debuglog('Running %s from lldb_run_command' % command)
            else:
                result.SetImmediateOutputFile(sys.__stdout__)

            command_args = shlex.split(command)
            lldb.debugger.HandleCommand('type category disable kernel')
            def_verbose_level = config['verbosity']

            # Filter out debugging arguments and enable logging
            debug_opts = [opt for opt in command_args if opt in _DEBUG_OPTS]
            command_args = [opt for opt in command_args if opt not in _DEBUG_OPTS]
            lldb_log_filename = None

            if "--radar" in debug_opts:
                lldb_log_filename = "/tmp/lldb.{:d}.log".format(int(time.time()))
                lldb_run_command("log enable --file {:s} lldb api".format(lldb_log_filename))
                lldb_run_command("log enable --file {:s} gdb-remote packets".format(lldb_log_filename))
                lldb_run_command("log enable --file {:s} kdp-remote packets".format(lldb_log_filename))

            try:
                stream.setOptions(command_args, option_string)
                if stream.verbose_level != 0:
                    config['verbosity'] +=  stream.verbose_level
                with RedirectStdStreams(stdout=stream), caching.ImplicitContext(exe_ctx):
                    args = { 'cmd_args': stream.target_cmd_args }
                    if option_string:
                        args['cmd_options'] = stream.target_cmd_options
                    if fancy:
                        args['O'] = stream
                    obj(**args)
            except KeyboardInterrupt:
                print("Execution interrupted by user")
            except (ArgumentError, NotImplementedError) as arg_error:
                if str(arg_error) != HELP_ARGUMENT_EXCEPTION_SENTINEL:
                    formatted_err = f"{type(arg_error).__name__}: {arg_error}"
                    print(formatted_err)
                    result.SetError(formatted_err)
                print("{0:s}:\n        {1:s}".format(cmd_name, obj.__doc__.strip()))
                return False
            except Exception as exc:
                if "--radar" in debug_opts: lldb_run_command("log disable")
                return diagnostic_report(result, exc, stream, cmd_name, debug_opts, lldb_log_filename)

            if config['showTypeSummary']:
                lldb.debugger.HandleCommand('type category enable kernel' )

            if stream.pluginRequired :
                plugin = LoadXNUPlugin(stream.pluginName)
                if plugin == None :
                    print("Could not load plugins."+stream.pluginName)
                    return
                plugin.plugin_init(kern, config, lldb, kern.IsDebuggerConnected())
                return_data = plugin.plugin_execute(cmd_name, result.GetOutput())
                ProcessXNUPluginResult(return_data)
                plugin.plugin_cleanup()

            #restore the verbose level after command is complete
            config['verbosity'] = def_verbose_level

            return

        myglobals = globals()
        command_function_name = obj.__name__+"Command"
        myglobals[command_function_name] =  _internal_command_function
        myglobals[f"XnuCommandSentinel{cmd_name}"] = None
        command_function = myglobals[command_function_name]
        if not obj.__doc__:
            print("ERROR: Cannot register command({:s}) without documentation".format(cmd_name))
            return obj
        obj.__doc__ += "\n" + COMMON_HELP_STRING
        command_function.__doc__ = obj.__doc__
        global lldb_command_documentation
        lldb_command_documentation[cmd_name] = (obj.__name__, obj.__doc__.lstrip(), option_string)

        script_add_command = f"command script add -o -f {MODULE_NAME}.{command_function_name} {cmd_name}"
        lldb.debugger.HandleCommand(script_add_command)

        setattr(obj, 'fancy', fancy)
        if fancy:
            @wraps(obj)
            def wrapped_fun(cmd_args=None, cmd_options={}, O=None):
                if O is None:
                    stream = CommandOutput(cmd_name, fhandle=sys.stdout)
                    with RedirectStdStreams(stdout=stream):
                        return obj(cmd_args, cmd_options, O=stream)
                else:
                    return obj(cmd_args, cmd_options, O)
            return wrapped_fun
        return obj
    return _cmd


def lldb_alias(alias_name, cmd_line):
    """ define an alias in the lldb command line.
        A programatic way of registering an alias. This basically does
        (lldb)command alias alias_name "cmd_line"
        ex.
        lldb_alias('readphys16', 'readphys 16')
    """
    alias_name = alias_name.strip()
    cmd_line = cmd_line.strip()
    lldb.debugger.HandleCommand("command alias " + alias_name + " "+ cmd_line)

def SetupLLDBTypeSummaries(reset=False):
    global lldb_summary_definitions, MODULE_NAME
    if reset:
            lldb.debugger.HandleCommand("type category delete  kernel ")
    for single_type in list(lldb_summary_definitions.keys()):
        summary_function = lldb_summary_definitions[single_type]
        lldb_cmd = "type summary add \""+ single_type +"\" --category kernel --python-function " + MODULE_NAME + ".LLDBSummary" + summary_function.__name__
        debuglog(lldb_cmd)
        lldb.debugger.HandleCommand(lldb_cmd)
    if config['showTypeSummary']:
            lldb.debugger.HandleCommand("type category enable  kernel")
    else:
            lldb.debugger.HandleCommand("type category disable kernel")

    return

def LoadXNUPlugin(name):
    """ Try to load a plugin from the plugins directory.
    """
    retval = None
    name=name.strip()
    try:
        module_obj = __import__('plugins.'+name, globals(), locals(), [], -1)
        module_obj = module_obj.__dict__[name]
        defs = dir(module_obj)
        if 'plugin_init' in defs and 'plugin_execute' in defs and 'plugin_cleanup' in defs:
            retval = module_obj
        else:
            print("Plugin is not correctly implemented. Please read documentation on implementing plugins")
    except:
        print("plugin not found :"+name)

    return retval

def ProcessXNUPluginResult(result_data):
    """ Look at the returned data from plugin and see if anymore actions are required or not
        params: result_data - list of format (status, out_string, more_commands)
    """
    ret_status = result_data[0]
    ret_string = result_data[1]
    ret_commands = result_data[2]

    if not ret_status:
        print("Plugin failed: " + ret_string)
        return
    print(ret_string)
    if len(ret_commands) >= 0:
        for cmd in ret_commands:
            print("Running command on behalf of plugin:" + cmd)
            lldb.debugger.HandleCommand(cmd)
    return

# holds tests registered with xnu.
#DONOTTOUCHME: Exclusive use of xnudebug_test only
lldb_command_tests = {}
def xnudebug_test(test_name):
    """ A function decoratore to register a test with the framework. Each test is supposed to be of format
        def Test<name>(kernel_target, config, lldb_obj, isConnected )

        NOTE: The testname should start with "Test" else exception will be raised.
    """
    def _test(obj):
        global lldb_command_tests
        if obj.__name__.find("Test") != 0 :
            print("Test name ", obj.__name__ , " should start with Test")
            raise ValueError
        lldb_command_tests[test_name] = (test_name, obj.__name__, obj, obj.__doc__)
        return obj
    return _test


# End Debugging specific utility functions
# Kernel Debugging specific classes and accessor methods

# global access object for target kernel

def GetObjectAtIndexFromArray(array_base: value, index: int):
    """ Subscript indexing for arrays that are represented in C as pointers.
        for ex. int *arr = malloc(20*sizeof(int));
        now to get 3rd int from 'arr' you'd do
        arr[2] in C
        GetObjectAtIndexFromArray(arr_val,2)
        params:
            array_base : core.value - representing a pointer type (ex. base of type 'ipc_entry *')
            index : int - 0 based index into the array
        returns:
            core.value : core.value of the same type as array_base_val but pointing to index'th element
    """
    array_base_val = array_base.GetSBValue()
    base_address = array_base_val.GetValueAsAddress()
    size = array_base_val.GetType().GetPointeeType().GetByteSize()
    obj_address = base_address + (index * size)
    obj = kern.CreateValueFromAddress(obj_address, array_base_val.GetType().GetPointeeType().name)
    return addressof(obj)


kern: KernelTarget = None

def GetLLDBThreadForKernelThread(thread_obj):
    """ Get a reference to lldb.SBThread representation for kernel thread.
        params:
            thread_obj : core.cvalue - thread object of type thread_t
        returns
            lldb.SBThread - lldb thread object for getting backtrace/registers etc.
    """
    tid = unsigned(thread_obj.thread_id)
    lldb_process = LazyTarget.GetProcess()
    sbthread = lldb_process.GetThreadByID(tid)
    if not sbthread.IsValid():
        # in case lldb doesnt know about this thread, create one
        if hasattr(lldb_process, "CreateOSPluginThread"):
            debuglog("creating os plugin thread on the fly for {0:d} 0x{1:x}".format(tid, thread_obj))
            lldb_process.CreateOSPluginThread(tid, unsigned(thread_obj))
        else:
            raise RuntimeError("LLDB process does not support CreateOSPluginThread.")
        sbthread = lldb_process.GetThreadByID(tid)

    if not sbthread.IsValid():
        raise RuntimeError("Unable to find lldb thread for tid={0:d} thread = {1:#018x} (#16049947: have you put 'settings set target.load-script-from-symbol-file true' in your .lldbinit?)".format(tid, thread_obj))

    return sbthread

def GetKextSymbolInfo(load_addr):
    """ Get a string descriptiong load_addr <kextname> + offset
        params:
            load_addr - int address value of pc in backtrace.
        returns: str - kext name + offset string. If no cached data available, warning message is returned.
    """
    symbol_name = "None"
    symbol_offset = load_addr
    kmod_val = kern.globals.kmod
    if not kern.arch.startswith('arm64'):
        for kval in IterateLinkedList(kmod_val, 'next'):
            if load_addr >= unsigned(kval.address) and \
                load_addr <= (unsigned(kval.address) + unsigned(kval.size)):
                symbol_name = kval.name
                symbol_offset = load_addr - unsigned(kval.address)
                break
        return "{:#018x} {:s} + {:#x} \n".format(load_addr, symbol_name, symbol_offset)

    # only for arm64 we do lookup for split kexts.
    if not GetAllKextSummaries.cached():
        if str(GetConnectionProtocol()) != "core":
            return "{:#018x} ~ kext info not available. please run 'showallkexts' once ~ \n".format(load_addr)

    for kval in GetAllKextSummaries():
        text_seg = text_segment(kval.segments)
        if load_addr >= text_seg.vmaddr and \
            load_addr <= (text_seg.vmaddr + text_seg.vmsize):
            symbol_name = kval.name
            symbol_offset = load_addr - text_seg.vmaddr
            break
    return "{:#018x} {:s} + {:#x} \n".format(load_addr, symbol_name, symbol_offset)

def GetThreadBackTrace(thread_obj: value, verbosity = vHUMAN, prefix = ""):
    """ Get a string to display back trace for a thread.
        params:
            thread_obj - core.cvalue : a thread object of type thread_t.
            verbosity - int : either of vHUMAN, vSCRIPT or vDETAIL to describe the verbosity of output
            prefix - str : a string prefix added before the line for each frame.
            isContinuation - bool : is thread a continuation?
        returns:
            str - a multi line string showing each frame in backtrace.
    """
    kernel_stack = unsigned(thread_obj.kernel_stack)
    is_continuation = not bool(kernel_stack)
    thread_val = GetLLDBThreadForKernelThread(thread_obj)
    out_string = ""
    reserved_stack = unsigned(thread_obj.reserved_stack)
    if not is_continuation:
        if kernel_stack and reserved_stack:
            out_string += f"{prefix}reserved_stack = {reserved_stack:#018x}\n"
        out_string += f"{prefix}kernel_stack = {kernel_stack:#018x}\n"
    else:
        out_string += prefix + "continuation ="
    iteration = 0
    last_frame_p = 0
    for frame in thread_val.frames:
        addr = frame.GetPCAddress()
        load_addr = addr.GetLoadAddress(LazyTarget.GetTarget())
        function = frame.GetFunction()
        frame_p = frame.GetFP()
        mod_name = frame.GetModule().GetFileSpec().GetFilename()

        if iteration == 0 and not is_continuation:
            out_string += f"{prefix}stacktop = {frame_p:#018x}\n"

        if not function:
            # No debug info for 'function'.
            out_string += prefix
            if not is_continuation:
                out_string += f"{frame_p:#018x} "

            symbol = frame.GetSymbol()
            if not symbol:
                out_string += GetKextSymbolInfo(load_addr)
            else:
                file_addr = addr.GetFileAddress()
                start_addr = symbol.GetStartAddress().GetFileAddress()
                symbol_name = symbol.GetName()
                symbol_offset = file_addr - start_addr
                out_string += f"{load_addr:#018x} {mod_name}`{symbol_name} + {symbol_offset:#x} \n"
        else:
            # Debug info is available for 'function'.
            inlined_suffix= " [inlined]" if frame.IsInlined() else ''
            func_name = f"{frame.GetFunctionName()}{inlined_suffix}"
            # file_name = frame.GetLineEntry().GetFileSpec().GetFilename()
            # line_num = frame.GetLineEntry().GetLine()
            if is_continuation and frame.IsInlined():
                debuglog("Skipping frame for thread {:#018x} since its inlined".format(thread_obj))
                continue
            out_string += prefix
            if not is_continuation:
                out_string += f"{frame_p:#018x} "

            if len(frame.arguments) > 0:
                func_args = str(frame.arguments).replace('\n', ', ')
                out_string += f"{load_addr:#018x} {func_name}({func_args}) \n"
            else:
                out_string += f"{load_addr:#018x} {func_name}(void) \n"

        iteration += 1
        if frame_p:
            last_frame_p = frame_p

    if not is_continuation and last_frame_p:
        out_string += prefix + "stackbottom = {:#018x}".format(last_frame_p)
    out_string = out_string.replace("variable not available","")
    return out_string

def GetSourceInformationForAddress(addr):
    """ convert and address to function +offset information.
        params: addr - int address in the binary to be symbolicated
        returns: string of format "0xaddress: function + offset"
    """
    try:
        return str(kern.SymbolicateFromAddress(addr, fullSymbol=True)[0])
    except:
        return '{0:<#x} <unknown: use `addkextaddr {0:#x}` to resolve>'.format(addr)

def GetFrameLocalVariable(variable_name, frame_no=0):
    """ Find a local variable by name
        params:
          variable_name: str - name of variable to search for
        returns:
          core.value - if the variable is found.
          None   - if not found or not Valid
    """
    retval = None
    sbval = None
    lldb_SBThread = LazyTarget.GetProcess().GetSelectedThread()
    frame = lldb_SBThread.GetSelectedFrame()
    if frame_no :
      frame = lldb_SBThread.GetFrameAtIndex(frame_no)
    if frame :
      sbval = frame.FindVariable(variable_name)
    if sbval and sbval.IsValid():
      retval = core.cvalue.value(sbval)
    return retval

# Begin Macros for kernel debugging

@lldb_command('kgmhelp')
def KernelDebugCommandsHelp(cmd_args=None):
    """ Show a list of registered commands for kenel debugging.
    """
    global lldb_command_documentation
    print("List of commands provided by " + MODULE_NAME + " for kernel debugging.")
    cmds = list(lldb_command_documentation.keys())
    cmds.sort()
    for cmd in cmds:
        if isinstance(lldb_command_documentation[cmd][-1], str):
            print(" {0: <20s} - {1}".format(cmd , lldb_command_documentation[cmd][1].split("\n")[0].strip()))
        else:
            print(" {0: <20s} - {1}".format(cmd , "No help string found."))
    print('Each of the functions listed here accept the following common options. ')
    print(COMMON_HELP_STRING)
    print('Additionally, each command implementation may have more options. "(lldb) help <command> " will show these options.')
    return None


@lldb_command('showraw')
def ShowRawCommand(cmd_args=None):
    """ A command to disable the kernel summaries and show data as seen by the system.
        This is useful when trying to read every field of a struct as compared to brief summary

        Usage: showraw foo_command foo_arg1 foo_arg2 ...
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("'showraw' requires a command to run")

    command = " ".join(cmd_args)
    lldb.debugger.HandleCommand('type category disable kernel' )
    lldb.debugger.HandleCommand(command)
    lldb.debugger.HandleCommand('type category enable kernel' )


@lldb_command('xnudebug')
def XnuDebugCommand(cmd_args=None):
    """  command interface for operating on the xnu macros. Allowed commands are as follows
        reload:
            Reload a submodule from the xnu/tools/lldb directory. Do not include the ".py" suffix in modulename.
            usage: xnudebug reload <modulename> (eg. memory, process, stats etc)
        flushcache:
            remove any cached data held in static or dynamic data cache.
            usage: xnudebug flushcache
        test:
            Start running registered test with <name> from various modules.
            usage: xnudebug test <name> (eg. test_memstats)
        testall:
            Go through all registered tests and run them
        debug:
            Toggle state of debug configuration flag.
        profile:
            Profile an lldb command and write its profile info to a file.
            usage: xnudebug profile <path_to_profile> <cmd...>

            e.g. `xnudebug profile /tmp/showallstacks_profile.prof showallstacks
        coverage:
            Collect coverage for an lldb command and save it to a file.
            usage: xnudebug coverage <path_to_coverage_file> <cmd ...>

            e.g. `xnudebug coverage /tmp/showallstacks_coverage.cov showallstacks`
            An HTML report can then be generated via `coverage html --data-file=<path>` 
    """
    global config
    command_args = cmd_args
    if len(command_args) == 0:
        raise ArgumentError("No command specified.")
    supported_subcommands = ['debug', 'reload', 'test', 'testall', 'flushcache', 'profile', 'coverage']
    subcommand = GetLongestMatchOption(command_args[0], supported_subcommands, True)

    if len(subcommand) == 0:
        raise ArgumentError("Subcommand (%s) is not a valid command. " % str(command_args[0]))

    subcommand = subcommand[0].lower()
    if subcommand == 'debug':
        if command_args[-1].lower().find('dis') >=0 and config['debug']:
            config['debug'] = False
            print("Disabled debug logging.")
        elif command_args[-1].lower().find('dis') < 0 and not config['debug']:
            config['debug'] = True
            EnableLLDBAPILogging()  # provided by utils.py
            print("Enabled debug logging. \nPlease run 'xnudebug debug disable' to disable it again. ")

    if subcommand == 'flushcache':
        print("Current size of cache: {}".format(caching.GetSizeOfCache()))
        caching.ClearAllCache()

    if subcommand == 'reload':
        module_name = command_args[-1]
        if module_name in sys.modules:
            reload(sys.modules[module_name])
            print(module_name + " is reloaded from " + sys.modules[module_name].__file__)
        else:
            print("Unable to locate module named ", module_name)

    if subcommand == 'testall':
        for test_name in list(lldb_command_tests.keys()):
            print("[BEGIN]", test_name)
            res = lldb_command_tests[test_name][2](kern, config, lldb, True)
            if res:
                print("[PASSED] {:s}".format(test_name))
            else:
                print("[FAILED] {:s}".format(test_name))

    if subcommand == 'test':
        test_name = command_args[-1]
        if test_name in lldb_command_tests:
            test = lldb_command_tests[test_name]
            print("Running test {:s}".format(test[0]))
            if test[2](kern, config, lldb, True) :
                print("[PASSED] {:s}".format(test[0]))
            else:
                print("[FAILED] {:s}".format(test[0]))
            return ""
        else:
            print("No such test registered with name: {:s}".format(test_name))
            print("XNUDEBUG Available tests are:")
            for i in list(lldb_command_tests.keys()):
                print(i)
        return None

    if subcommand == 'profile':
        save_path = command_args[1]

        import cProfile, pstats, io

        pr = cProfile.Profile()
        pr.enable()

        lldb.debugger.HandleCommand(" ".join(command_args[2:]))

        pr.disable()
        pr.dump_stats(save_path)

        print("")
        print("=" * 80)
        print("")

        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.strip_dirs()
        ps.sort_stats('cumulative')
        ps.print_stats(30)
        print(s.getvalue().rstrip())
        print("")

        print(f"Profile info saved to \"{save_path}\"")

    if subcommand == 'coverage':
        coverage_module = find_spec('coverage')
        if not coverage_module:
            print("Missing 'coverage' module. Please install it for the interpreter currently running.`")
            return
        
        save_path = command_args[1]

        import coverage
        cov = coverage.Coverage(data_file=save_path)
        cov.start()

        lldb.debugger.HandleCommand(" ".join(command_args[2:]))

        cov.stop()
        cov.save()

        print(cov.report())
        print(f"Coverage info saved to: \"{save_path}\"")
        

    return False



@lldb_command('showversion')
def ShowVersion(cmd_args=None):
    """ Read the kernel version string from a fixed address in low
        memory. Useful if you don't know which kernel is on the other end,
        and need to find the appropriate symbols. Beware that if you've
        loaded a symbol file, but aren't connected to a remote target,
        the version string from the symbol file will be displayed instead.
        This macro expects to be connected to the remote kernel to function
        correctly.

    """
    print(kern.version)

def ProcessPanicStackshot(panic_stackshot_addr, panic_stackshot_len, cmd_options):
    """ Process the panic stackshot from the panic header, saving it to a file if it is valid
        params: panic_stackshot_addr : start address of the panic stackshot binary data
                panic_stackshot_len : length of the stackshot binary data
        returns: nothing
    """
    if not panic_stackshot_addr:
        print("No panic stackshot available (invalid addr)")
        return

    if not panic_stackshot_len:
        print("No panic stackshot available (zero length)")
        return;

    if "-D" in cmd_options:
        dir_ = cmd_options["-D"]
        if os.path.exists(dir_):
            if not os.access(dir_, os.W_OK):
                print("Write access to {} denied".format(dir_))
                return
        else:
            try:
                os.makedirs(dir_)
            except OSError as e:
                print("An error occurred {} while creating a folder : {}".format(e, dir_))
                return
    else:
        dir_ = "/tmp"

    id = str(uuid.uuid4())[:8]
    ss_binfile = os.path.join(dir_, "panic_%s.bin" % id)
    ss_ipsfile = os.path.join(dir_, "panic_%s.ips" % id)

    if not SaveDataToFile(panic_stackshot_addr, panic_stackshot_len, ss_binfile, None):
        print("Failed to save stackshot binary data to file")
        return

    from kcdata import decode_kcdata_file
    try:
        with open(ss_binfile, "rb") as binfile:
            decode_kcdata_file(binfile, ss_ipsfile)
        print("Saved ips stackshot file as %s" % ss_ipsfile)
    except Exception as e:
        print("Failed to decode the stackshot: %s" % str(e))

def ParseEmbeddedPanicLog(panic_header, cmd_options={}):
    panic_buf = Cast(panic_header, 'char *')
    panic_log_magic = unsigned(panic_header.eph_magic)
    panic_log_begin_offset = unsigned(panic_header.eph_panic_log_offset)
    panic_log_len = unsigned(panic_header.eph_panic_log_len)
    other_log_begin_offset = unsigned(panic_header.eph_other_log_offset)
    other_log_len = unsigned(panic_header.eph_other_log_len)
    expected_panic_magic = xnudefines.EMBEDDED_PANIC_MAGIC
    panic_stackshot_addr = unsigned(panic_header) + unsigned(panic_header.eph_stackshot_offset)
    panic_stackshot_len = unsigned(panic_header.eph_stackshot_len)
    panic_header_flags = unsigned(panic_header.eph_panic_flags)

    warn_str = ""
    out_str = ""

    if panic_log_magic != 0 and panic_log_magic != expected_panic_magic:
        warn_str += "BAD MAGIC! Found 0x%x expected 0x%x" % (panic_log_magic,
                    expected_panic_magic)

    if warn_str:
        print("\n %s" % warn_str)
        if panic_log_begin_offset == 0:
            return

    if "-S" in cmd_options:
        if panic_header_flags & xnudefines.EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG:
            ProcessPanicStackshot(panic_stackshot_addr, panic_stackshot_len, cmd_options)
        else:
            print("No panic stackshot available")
    elif "-D" in cmd_options:
        print("-D option must be specified along with the -S option")
        return

    panic_log_curindex = 0
    while panic_log_curindex < panic_log_len:
        p_char = str(panic_buf[(panic_log_begin_offset + panic_log_curindex)])
        out_str += p_char
        panic_log_curindex += 1

    if other_log_begin_offset != 0:
        other_log_curindex = 0
        while other_log_curindex < other_log_len:
            p_char = str(panic_buf[(other_log_begin_offset + other_log_curindex)])
            out_str += p_char
            other_log_curindex += 1

    print(out_str)
    return

def ParseMacOSPanicLog(panic_header, cmd_options={}):
    panic_buf = Cast(panic_header, 'char *')
    panic_log_magic = unsigned(panic_header.mph_magic)
    panic_log_begin_offset = unsigned(panic_header.mph_panic_log_offset)
    panic_log_len = unsigned(panic_header.mph_panic_log_len)
    other_log_begin_offset = unsigned(panic_header.mph_other_log_offset)
    other_log_len = unsigned(panic_header.mph_other_log_len)
    cur_debug_buf_ptr_offset = (unsigned(kern.globals.debug_buf_ptr) - unsigned(panic_header))
    if other_log_begin_offset != 0 and (other_log_len == 0 or other_log_len < (cur_debug_buf_ptr_offset - other_log_begin_offset)):
        other_log_len = cur_debug_buf_ptr_offset - other_log_begin_offset
    expected_panic_magic = xnudefines.MACOS_PANIC_MAGIC

    # use the global if it's available (on an x86 corefile), otherwise refer to the header
    if hasattr(kern.globals, "panic_stackshot_buf"):
        panic_stackshot_addr = unsigned(kern.globals.panic_stackshot_buf)
        panic_stackshot_len = unsigned(kern.globals.panic_stackshot_len)
    else:
        panic_stackshot_addr = unsigned(panic_header) + unsigned(panic_header.mph_stackshot_offset)
        panic_stackshot_len = unsigned(panic_header.mph_stackshot_len)

    panic_header_flags = unsigned(panic_header.mph_panic_flags)

    warn_str = ""
    out_str = ""

    if panic_log_magic != 0 and panic_log_magic != expected_panic_magic:
        warn_str += "BAD MAGIC! Found 0x%x expected 0x%x" % (panic_log_magic,
                    expected_panic_magic)

    if warn_str:
        print("\n %s" % warn_str)
        if panic_log_begin_offset == 0:
            return

    if "-S" in cmd_options:
        if panic_header_flags & xnudefines.MACOS_PANIC_STACKSHOT_SUCCEEDED_FLAG:
            ProcessPanicStackshot(panic_stackshot_addr, panic_stackshot_len, cmd_options)
        else:
            print("No panic stackshot available")
    elif "-D" in cmd_options:
        print("-D option must be specified along with the -S option")
        return

    panic_log_curindex = 0
    while panic_log_curindex < panic_log_len:
        p_char = str(panic_buf[(panic_log_begin_offset + panic_log_curindex)])
        out_str += p_char
        panic_log_curindex += 1

    if other_log_begin_offset != 0:
        other_log_curindex = 0
        while other_log_curindex < other_log_len:
            p_char = str(panic_buf[(other_log_begin_offset + other_log_curindex)])
            out_str += p_char
            other_log_curindex += 1

    print(out_str)
    return

def ParseAURRPanicLog(panic_header, cmd_options={}):
    reset_cause = {
        0x0: "OTHER",
        0x1: "CATERR",
        0x2: "SWD_TIMEOUT",
        0x3: "GLOBAL RESET",
        0x4: "STRAIGHT TO S5",
    }

    expected_panic_magic = xnudefines.AURR_PANIC_MAGIC

    panic_buf = Cast(panic_header, 'char *')

    try:
        # This line will blow up if there's not type info for this struct (older kernel)
        # We fall back to manual parsing below
        aurr_panic_header = Cast(panic_header, 'struct efi_aurr_panic_header *')
        panic_log_magic = unsigned(aurr_panic_header.efi_aurr_magic)
        panic_log_version = unsigned(aurr_panic_header.efi_aurr_version)
        panic_log_reset_cause = unsigned(aurr_panic_header.efi_aurr_reset_cause)
        panic_log_reset_log_offset = unsigned(aurr_panic_header.efi_aurr_reset_log_offset)
        panic_log_reset_log_len = unsigned(aurr_panic_header.efi_aurr_reset_log_len)
    except Exception as e:
        print("*** Warning: kernel symbol file has no type information for 'struct efi_aurr_panic_header'...")
        print("*** Warning: trying to manually parse...")
        aurr_panic_header = Cast(panic_header, "uint32_t *")
        panic_log_magic = unsigned(aurr_panic_header[0])
        # panic_log_crc = unsigned(aurr_panic_header[1])
        panic_log_version = unsigned(aurr_panic_header[2])
        panic_log_reset_cause = unsigned(aurr_panic_header[3])
        panic_log_reset_log_offset = unsigned(aurr_panic_header[4])
        panic_log_reset_log_len = unsigned(aurr_panic_header[5])

    if panic_log_magic != 0 and panic_log_magic != expected_panic_magic:
        print("BAD MAGIC! Found 0x%x expected 0x%x" % (panic_log_magic,
                    expected_panic_magic))
        return

    print("AURR Panic Version: %d" % (panic_log_version))

    # When it comes time to extend this in the future, please follow the
    # construct used below in ShowPanicLog()
    if panic_log_version in (xnudefines.AURR_PANIC_VERSION, xnudefines.AURR_CRASHLOG_PANIC_VERSION):
        # AURR Report Version 1 (AURR/MacEFI) or 2 (Crashlog)
        # see macefifirmware/Vendor/Apple/EfiPkg/AppleDebugSupport/Library/Debugger.h
        print("Reset Cause: 0x%x (%s)" % (panic_log_reset_cause, reset_cause.get(panic_log_reset_cause, "UNKNOWN")))

        # Adjust panic log string length (cap to maximum supported values)
        if panic_log_version == xnudefines.AURR_PANIC_VERSION:
            max_string_len = panic_log_reset_log_len
        elif panic_log_version == xnudefines.AURR_CRASHLOG_PANIC_VERSION:
            max_string_len = xnudefines.CRASHLOG_PANIC_STRING_LEN

        panic_str_offset = 0
        out_str = ""

        while panic_str_offset < max_string_len:
            p_char = str(panic_buf[panic_log_reset_log_offset + panic_str_offset])
            out_str += p_char
            panic_str_offset += 1

        print(out_str)

        # Save Crashlog Binary Data (if available)
        if "-S" in cmd_options and panic_log_version == xnudefines.AURR_CRASHLOG_PANIC_VERSION:
            crashlog_binary_offset = panic_log_reset_log_offset + xnudefines.CRASHLOG_PANIC_STRING_LEN
            crashlog_binary_size = (panic_log_reset_log_len > xnudefines.CRASHLOG_PANIC_STRING_LEN) and (panic_log_reset_log_len - xnudefines.CRASHLOG_PANIC_STRING_LEN) or 0

            if 0 == crashlog_binary_size:
                print("No crashlog data found...")
                return

            # Save to file
            ts = int(time.time())
            ss_binfile = "/tmp/crashlog_%d.bin" % ts

            if not SaveDataToFile(panic_buf + crashlog_binary_offset, crashlog_binary_size, ss_binfile, None):
                print("Failed to save crashlog binary data to file")
                return
    else:
        return ParseUnknownPanicLog(panic_header, cmd_options)

    return

def ParseUnknownPanicLog(panic_header, cmd_options={}):
    magic_ptr = Cast(panic_header, 'uint32_t *')
    panic_log_magic = dereference(magic_ptr)
    print("Unrecognized panic header format. Magic: 0x%x..." % unsigned(panic_log_magic))
    print("Panic region starts at 0x%08x" % int(panic_header))
    print("Hint: To dump this panic header in order to try manually parsing it, use this command:")
    print(" (lldb) memory read -fx -s4 -c64 0x%08x" % int(panic_header))
    print(" ^ that will dump the first 256 bytes of the panic region")
    ## TBD: Hexdump some bits here to allow folks to poke at the region manually?
    return


@lldb_command('paniclog', 'SMD:')
def ShowPanicLog(cmd_args=None, cmd_options={}):
    """ Display the paniclog information
        usage: (lldb) paniclog
        options:
            -v : increase verbosity
            -S : parse stackshot data (if panic stackshot available)
            -D : Takes a folder name for stackshot. This must be specified along with the -S option.
            -M : parse macOS panic area (print panic string (if available), and/or capture crashlog info)
            -E : Takes a file name and redirects the ext paniclog output to the file
    """

    if "-M" in cmd_options:
        if not hasattr(kern.globals, "mac_panic_header"):
            print("macOS panic data requested but unavailable on this device")
            return
        panic_header = kern.globals.mac_panic_header
        # DEBUG HACK FOR TESTING
        #panic_header = kern.GetValueFromAddress(0xfffffff054098000, "uint32_t *")
    else:
        panic_header = kern.globals.panic_info

    if hasattr(panic_header, "eph_magic"):
        panic_log_magic = unsigned(panic_header.eph_magic)
    elif hasattr(panic_header, "mph_magic"):
        panic_log_magic = unsigned(panic_header.mph_magic)
    else:
        print("*** Warning: unsure of panic header format, trying anyway")
        magic_ptr = Cast(panic_header, 'uint32_t *')
        panic_log_magic = int(dereference(magic_ptr))

    if panic_log_magic == 0:
        # No panic here..
        return

    panic_parsers = {
        int(xnudefines.AURR_PANIC_MAGIC)     : ParseAURRPanicLog,
        int(xnudefines.MACOS_PANIC_MAGIC)    : ParseMacOSPanicLog,
        int(xnudefines.EMBEDDED_PANIC_MAGIC) : ParseEmbeddedPanicLog,
    }

    # Find the right parser (fall back to unknown parser above)
    parser = panic_parsers.get(panic_log_magic, ParseUnknownPanicLog)

    # execute it
    return parser(panic_header, cmd_options)

@lldb_command('extpaniclog', 'F:')
def ProcessExtensiblePaniclog(cmd_args=None, cmd_options={}):
    """ Write the extensible paniclog information to a file
        usage: (lldb) paniclog
        options:
            -F : Output file name
    """

    if not "-F" in cmd_options:
        print("Output file name is needed: Use -F")
        return

    panic_header = kern.globals.panic_info
    process = LazyTarget().GetProcess()
    error = lldb.SBError()
    EXT_PANICLOG_MAX_SIZE = 32 # 32 is the max size of the string in Data ID

    ext_paniclog_len = unsigned(panic_header.eph_ext_paniclog_len)
    if ext_paniclog_len == 0:
        print("Cannot find extensible paniclog")
        return

    ext_paniclog_addr = unsigned(panic_header) + unsigned(panic_header.eph_ext_paniclog_offset)

    ext_paniclog_bytes = process.chkReadMemory(ext_paniclog_addr, ext_paniclog_len);

    idx = 0;
    ext_paniclog_ver_bytes = ext_paniclog_bytes[idx:idx+sizeof('uint32_t')]
    ext_paniclog_ver = int.from_bytes(ext_paniclog_ver_bytes, 'little')

    idx += sizeof('uint32_t')
    no_of_logs_bytes = ext_paniclog_bytes[idx:idx+sizeof('uint32_t')]
    no_of_logs = int.from_bytes(no_of_logs_bytes, 'little')

    idx += sizeof('uint32_t')

    ext_paniclog = dict()

    logs_processed = 0
    for _ in range(no_of_logs):
        uuid_bytes = ext_paniclog_bytes[idx:idx+sizeof('uuid_t')]
        ext_uuid = str(uuid.UUID(bytes=uuid_bytes))

        idx += sizeof('uuid_t')
        flags_bytes = ext_paniclog_bytes[idx:idx+sizeof('uint32_t')]
        flags = int.from_bytes(flags_bytes, 'little')

        idx += sizeof('ext_paniclog_flags_t')
        data_id_bytes = ext_paniclog_bytes[idx:idx + EXT_PANICLOG_MAX_SIZE].split(b'\0')[0]
        data_id = data_id_bytes.decode('utf-8')
        data_id_len = len(data_id_bytes)

        idx += data_id_len + 1
        data_len_bytes = ext_paniclog_bytes[idx:idx+sizeof('uint32_t')]
        data_len = int.from_bytes(data_len_bytes, 'little')

        idx += sizeof('uint32_t')
        data_bytes = ext_paniclog_bytes[idx:idx+data_len]
        data = base64.b64encode(data_bytes).decode('ascii')

        idx += data_len

        temp_dict = dict(Data_Id=data_id, Data=data)

        ext_paniclog.setdefault(ext_uuid, []).append(temp_dict)

        logs_processed += 1

    if logs_processed < no_of_logs:
        print("** Warning: Extensible paniclog might be corrupted **")

    with open(cmd_options['-F'], 'w') as out_file:
        out_file.write(json.dumps(ext_paniclog))
        print("Wrote extensible paniclog to %s" % cmd_options['-F'])

    return

@lldb_command('showbootargs')
def ShowBootArgs(cmd_args=None):
    """ Display boot arguments passed to the target kernel
    """
    bootargs = Cast(kern.GetGlobalVariable('PE_state').bootArgs, 'boot_args *')
    bootargs_cmd = bootargs.CommandLine
    print(str(bootargs_cmd))

# The initialization code to add your commands
_xnu_framework_init = False
def __lldb_init_module(debugger: lldb.SBDebugger, internal_dict):
    global kern, lldb_command_documentation, config, _xnu_framework_init
    if _xnu_framework_init:
        return
    _xnu_framework_init = True
    debugger.HandleCommand('type summary add --regex --summary-string "${var%s}" -C yes -p -v "char *\[[0-9]*\]"')
    debugger.HandleCommand('type format add --format hex -C yes uintptr_t')
    debugger.HandleCommand('type format add --format hex -C yes cpumap_t')
    kern = KernelTarget(debugger)
    if not hasattr(lldb.SBValue, 'GetValueAsAddress'):
        warn_str = "WARNING: lldb version is too old. Some commands may break. Please update to latest lldb."
        if os.isatty(sys.__stdout__.fileno()):
            warn_str = VT.DarkRed + warn_str + VT.Default
        print(warn_str)
    print("xnu debug macros loaded successfully. Run showlldbtypesummaries to enable type summaries.")
    # print(f"xnu debugger ID: {debugger.GetID()}")

__lldb_init_module(lldb.debugger, None)

@lldb_command("showlldbtypesummaries")
def ShowLLDBTypeSummaries(cmd_args=[]):
    """ Enable/Disable kernel type summaries. Default is disabled.
        Usage: showlldbtypesummaries [enable|disable]
        default is enable
    """
    global config
    action = "enable"
    trailer_msg = ''
    if len(cmd_args) > 0 and cmd_args[0].lower().find('disable') >=0:
        action = "disable"
        config['showTypeSummary'] = False
        trailer_msg = "Please run 'showlldbtypesummaries enable' to enable the summary feature."
    else:
        config['showTypeSummary'] = True
        SetupLLDBTypeSummaries(True)
        trailer_msg = "Please run 'showlldbtypesummaries disable' to disable the summary feature."
    lldb_run_command("type category "+ action +" kernel")
    print("Successfully "+action+"d the kernel type summaries. %s" % trailer_msg)

@lldb_command('walkqueue_head', 'S')
def WalkQueueHead(cmd_args=[], cmd_options={}):
    """ walk a queue_head_t and list all members in it. Note this is for queue_head_t. refer to osfmk/kern/queue.h
        Option: -S - suppress summary output.
        Usage: (lldb) walkqueue_head  <queue_entry *> <struct type> <fieldname>
        ex:    (lldb) walkqueue_head  0x7fffff80 "thread *" "task_threads"

    """
    global lldb_summary_definitions
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("invalid arguments")
    if len(cmd_args) != 3:
        raise ArgumentError("insufficient arguments")
    queue_head = kern.GetValueFromAddress(cmd_args[0], 'struct queue_entry *')
    el_type = cmd_args[1]
    field_name = cmd_args[2]
    showsummary = False
    if el_type in lldb_summary_definitions:
        showsummary = True
    if '-S' in cmd_options:
        showsummary = False

    for i in IterateQueue(queue_head, el_type, field_name):
        if showsummary:
            print(lldb_summary_definitions[el_type](i))
        else:
            print("{0: <#020x}".format(i))



@lldb_command('walklist_entry', 'SE')
def WalkList(cmd_args=[], cmd_options={}):
    """ iterate over a list as defined with LIST_ENTRY in bsd/sys/queue.h
        params:
            object addr  - value : address of object
            element_type - str   : Type of the next element
            field_name   - str   : Name of the field in next element's structure

        Options: -S - suppress summary output.
                 -E - Iterate using SLIST_ENTRYs

        Usage: (lldb) walklist_entry  <obj with list_entry *> <struct type> <fieldname>
        ex:    (lldb) walklist_entry  0x7fffff80 "struct proc *" "p_sibling"

    """
    global lldb_summary_definitions
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("invalid arguments")
    if len(cmd_args) != 3:
        raise ArgumentError("insufficient arguments")
    el_type = cmd_args[1]
    queue_head = kern.GetValueFromAddress(cmd_args[0], el_type)
    field_name = cmd_args[2]
    showsummary = False
    if el_type in lldb_summary_definitions:
        showsummary = True
    if '-S' in cmd_options:
        showsummary = False
    if '-E' in cmd_options:
        prefix = 's'
    else:
        prefix = ''
    elt = queue_head
    while unsigned(elt) != 0:
        i = elt
        elt = elt.__getattr__(field_name).__getattr__(prefix + 'le_next')
        if showsummary:
            print(lldb_summary_definitions[el_type](i))
        else:
            print("{0: <#020x}".format(i))

def trace_parse_Copt(Copt):
    """Parses the -C option argument and returns a list of CPUs
    """
    cpusOpt = Copt
    cpuList = cpusOpt.split(",")
    chosen_cpus = []
    for cpu_num_string in cpuList:
        try:
            if '-' in cpu_num_string:
                parts = cpu_num_string.split('-')
                if len(parts) != 2 or not (parts[0].isdigit() and parts[1].isdigit()):
                    raise ArgumentError("Invalid cpu specification: %s" % cpu_num_string)
                firstRange = int(parts[0])
                lastRange = int(parts[1])
                if firstRange >= kern.globals.real_ncpus or lastRange >= kern.globals.real_ncpus:
                    raise ValueError()
                if lastRange < firstRange:
                    raise ArgumentError("Invalid CPU range specified: `%s'" % cpu_num_string)
                for cpu_num in range(firstRange, lastRange + 1):
                    if cpu_num not in chosen_cpus:
                        chosen_cpus.append(cpu_num)
            else:
                chosen_cpu = int(cpu_num_string)
                if chosen_cpu < 0 or chosen_cpu >= kern.globals.real_ncpus:
                    raise ValueError()
                if chosen_cpu not in chosen_cpus:
                    chosen_cpus.append(chosen_cpu)
        except ValueError:
            raise ArgumentError("Invalid CPU number specified.  Valid range is 0..%d" % (kern.globals.real_ncpus - 1))

    return chosen_cpus


IDX_CPU = 0
IDX_RINGPOS = 1
IDX_RINGENTRY = 2
def Trace_cmd(cmd_args=[], cmd_options={}, headerString=lambda:"", entryString=lambda x:"", ring='', entries_per_cpu=0, max_backtraces=0):
    """Generic trace dumper helper function
    """

    if '-S' in cmd_options:
        field_arg = cmd_options['-S']
        try:
            getattr(kern.PERCPU_GET(ring, 0)[0], field_arg)
            sort_key_field_name = field_arg
        except AttributeError:
            raise ArgumentError("Invalid sort key field name `%s'" % field_arg)
    else:
            sort_key_field_name = 'start_time_abs'

    if '-C' in cmd_options:
        chosen_cpus = trace_parse_Copt(cmd_options['-C'])
    else:
        chosen_cpus = [x for x in range(kern.globals.real_ncpus)]

    try:
        limit_output_count = int(cmd_options['-N'])
    except ValueError:
        raise ArgumentError("Invalid output count `%s'" % cmd_options['-N']);
    except KeyError:
        limit_output_count = None
        
    reverse_sort = '-R' in cmd_options
    backtraces = '-B' in cmd_options

    # entries will be a list of 3-tuples, each holding the CPU on which the iotrace entry was collected,
    # the original ring index, and the iotrace entry. 
    entries = []
    for x in chosen_cpus:
        ring_slice = [(x, y, kern.PERCPU_GET(ring, x)[y]) for y in range(entries_per_cpu)]
        entries.extend(ring_slice)

    total_entries = len(entries)

    entries.sort(key=lambda x: getattr(x[IDX_RINGENTRY], sort_key_field_name), reverse=reverse_sort)

    if limit_output_count is not None and limit_output_count > total_entries:
        print ("NOTE: Output count `%d' is too large; showing all %d entries" % (limit_output_count, total_entries));
        limit_output_count = total_entries

    if len(chosen_cpus) < kern.globals.real_ncpus:
        print("NOTE: Limiting to entries from cpu%s %s" % ("s" if len(chosen_cpus) > 1 else "", str(chosen_cpus)))

    if limit_output_count is not None and limit_output_count < total_entries:
        entries_to_display = limit_output_count
        print("NOTE: Limiting to the %s" % ("first entry" if entries_to_display == 1 else ("first %d entries" % entries_to_display)))
    else:
        entries_to_display = total_entries

    print(headerString())

    for x in range(entries_to_display):
        print(entryString(entries[x]))

        if backtraces:
            for btidx in range(max_backtraces):
                nextbt = entries[x][IDX_RINGENTRY].backtrace[btidx]
                if nextbt == 0:
                    break
                print("\t" + GetSourceInformationForAddress(nextbt))


@lldb_command('iotrace', 'C:N:S:RB')
def IOTrace_cmd(cmd_args=[], cmd_options={}):
    """ Prints the iotrace ring buffers for all CPUs by default.
        Arguments:
          -B                              : Print backtraces for each ring entry
          -C <cpuSpec#>[,...,<cpuSpec#N>] : Limit trace entries to those generated by the specified CPUs (each cpuSpec can be a
                                            single CPU number or a range separated by a dash (e.g. "0-3"))
          -N <count>                      : Limit output to the first <count> entries (across all chosen CPUs)
          -R                              : Display results in reverse-sorted order (oldest first; default is newest-first)
          -S <sort_key_field_name>        : Sort output by specified iotrace_entry_t field name (instead of by timestamp)
    """
    MAX_IOTRACE_BACKTRACES = 16

    if not hasattr(kern.globals, 'iotrace_entries_per_cpu'):
        print("Sorry, iotrace is not supported.")
        return

    if kern.globals.iotrace_entries_per_cpu == 0:
        print("Sorry, iotrace is disabled.")
        return

    hdrString = lambda : "%-19s %-8s %-10s %-20s SZ  %-18s %-17s DATA" % (
        "START TIME",
        "DURATION",
        "CPU#[RIDX]",
        "      TYPE",
        "   VIRT ADDR",
        "   PHYS ADDR")

    entryString = lambda x : "%-20u(%6u) %6s[%02d] %-20s %-2d 0x%016x 0x%016x 0x%x" % (
        x[IDX_RINGENTRY].start_time_abs,
        x[IDX_RINGENTRY].duration,
        "CPU%d" % x[IDX_CPU],
        x[IDX_RINGPOS],
        str(x[IDX_RINGENTRY].iotype).split("=")[1].strip(),
        x[IDX_RINGENTRY].size,
        x[IDX_RINGENTRY].vaddr,
        x[IDX_RINGENTRY].paddr,
        x[IDX_RINGENTRY].val)

    Trace_cmd(cmd_args, cmd_options, hdrString, entryString, 'iotrace_ring',
        kern.globals.iotrace_entries_per_cpu, MAX_IOTRACE_BACKTRACES)


@lldb_command('ttrace', 'C:N:S:RB')
def TrapTrace_cmd(cmd_args=[], cmd_options={}):
    """ Prints the iotrace ring buffers for all CPUs by default.
        Arguments:
          -B                              : Print backtraces for each ring entry
          -C <cpuSpec#>[,...,<cpuSpec#N>] : Limit trace entries to those generated by the specified CPUs (each cpuSpec can be a
                                            single CPU number or a range separated by a dash (e.g. "0-3"))
          -N <count>                      : Limit output to the first <count> entries (across all chosen CPUs)
          -R                              : Display results in reverse-sorted order (oldest first; default is newest-first)
          -S <sort_key_field_name>        : Sort output by specified traptrace_entry_t field name (instead of by timestamp)
    """
    MAX_TRAPTRACE_BACKTRACES = 8

    if kern.arch != "x86_64":
        print("Sorry, ttrace is an x86-only command.")
        return

    hdrString = lambda : "%-30s CPU#[RIDX] VECT INTERRUPTED_THREAD PREMLV INTRLV INTERRUPTED_PC" % (
        "START TIME   (DURATION [ns])")
    entryString = lambda x : "%-20u(%6s) %8s[%02d] 0x%02x 0x%016x %6d %6d %s" % (
        x[IDX_RINGENTRY].start_time_abs,
        str(x[IDX_RINGENTRY].duration) if hex(x[IDX_RINGENTRY].duration) != "0xffffffffffffffff" else 'inprog',
        "CPU%d" % x[IDX_CPU],
        x[IDX_RINGPOS],
        int(x[IDX_RINGENTRY].vector),
        x[IDX_RINGENTRY].curthread,
        x[IDX_RINGENTRY].curpl,
        x[IDX_RINGENTRY].curil,
        GetSourceInformationForAddress(x[IDX_RINGENTRY].interrupted_pc))

    Trace_cmd(cmd_args, cmd_options, hdrString, entryString, 'traptrace_ring',
        kern.globals.traptrace_entries_per_cpu, MAX_TRAPTRACE_BACKTRACES)

# Yields an iterator over all the sysctls from the provided root.
# Can optionally filter by the given prefix
def IterateSysctls(root_oid, prefix="", depth = 0, parent = ""):
    headp = root_oid
    for pp in IterateListEntry(headp, 'oid_link', 's'):
        node_str = ""
        if prefix != "":
            node_str = str(pp.oid_name)
            if parent != "":
                node_str = parent + "." + node_str
                if node_str.startswith(prefix):
                    yield pp, depth, parent
        else:
            yield pp, depth, parent
        type = pp.oid_kind & 0xf
        if type == 1 and pp.oid_arg1 != 0:
            if node_str == "":
                next_parent = str(pp.oid_name)
                if parent != "":
                    next_parent = parent + "." + next_parent
            else:
                next_parent = node_str
            # Only recurse if the next parent starts with our allowed prefix.
            # Note that it's OK if the parent string is too short (because the prefix might be for a deeper node).
            prefix_len = min(len(prefix), len(next_parent))
            if next_parent[:prefix_len] == prefix[:prefix_len]:
                for x in IterateSysctls(Cast(pp.oid_arg1, "struct sysctl_oid_list *"), prefix, depth + 1, next_parent):
                    yield x

@lldb_command('showsysctls', 'P:')
def ShowSysctls(cmd_args=[], cmd_options={}):
    """ Walks the list of sysctl data structures, printing out each during traversal.
        Arguments:
          -P <string> : Limit output to sysctls starting with the specified prefix.
    """
    if '-P' in cmd_options:
        _ShowSysctl_prefix = cmd_options['-P']
        allowed_prefixes = _ShowSysctl_prefix.split('.')
        if allowed_prefixes:
            for x in range(1, len(allowed_prefixes)):
                allowed_prefixes[x] = allowed_prefixes[x - 1] + "." + allowed_prefixes[x]
    else:
        _ShowSysctl_prefix = ''
        allowed_prefixes = []

    for sysctl, depth, parentstr in IterateSysctls(kern.globals.sysctl__children, _ShowSysctl_prefix):
        if parentstr == "":
            parentstr = "<none>"
        headp = sysctl
        st = (" " * depth * 2) + str(sysctl.GetSBValue().Dereference()).replace("\n", "\n" + (" " * depth * 2))
        print('parent = "%s"' % parentstr, st[st.find("{"):])

@lldb_command('showexperiments', 'F')
def ShowExperiments(cmd_args=[], cmd_options={}):
    """ Shows any active kernel experiments being run on the device via trial.
        Arguments:
        -F: Scan for changed experiment values even if no trial identifiers have been set.
    """
    treatment_id = str(kern.globals.trial_treatment_id)
    experiment_id = str(kern.globals.trial_experiment_id)
    deployment_id = kern.globals.trial_deployment_id._GetValueAsSigned()
    if treatment_id == "" and experiment_id == "" and deployment_id == -1:
        print("Device is not enrolled in any kernel experiments.")
        if not '-F' in cmd_options:
            return
    else:
        print("""Device is enrolled in a kernel experiment:
    treatment_id: %s
    experiment_id: %s
    deployment_id: %d""" % (treatment_id, experiment_id, deployment_id))

    print("Scanning sysctl tree for modified factors...")

    kExperimentFactorFlag = 0x00100000
    
    formats = {
            "IU": gettype("unsigned int *"),
            "I": gettype("int *"),
            "LU": gettype("unsigned long *"),
            "L": gettype("long *"),
            "QU": gettype("uint64_t *"),
            "Q": gettype("int64_t *")
    }

    for sysctl, depth, parentstr in IterateSysctls(kern.globals.sysctl__children):
        if sysctl.oid_kind & kExperimentFactorFlag:
            spec = cast(sysctl.oid_arg1, "struct experiment_spec *")
            # Skip if arg2 isn't set to 1 (indicates an experiment factor created without an experiment_spec).
            if sysctl.oid_arg2 == 1:
                if spec.modified == 1:
                    fmt = str(sysctl.oid_fmt)
                    ptr = spec.ptr
                    t = formats.get(fmt, None)
                    if t:
                        value = cast(ptr, t)
                    else:
                        # Unknown type
                        continue
                    name = str(parentstr) + "." + str(sysctl.oid_name)
                    print("%s = %d (Default value is %d)" % (name, dereference(value), spec.original_value))


from memory import *
from process import *
from ipc import *
from pmap import *
from ioreg import *
from mbufs import *
from net import *
from skywalk import *
from kext import *
from kdp import *
from userspace import *
from pci import *
from scheduler import *
from recount import *
from misc import *
from apic import *
from structanalyze import *
from ipcimportancedetail import *
from bank import *
from turnstile import *
from kasan import *
from waitq import *
from usertaskgdbserver import *
from ktrace import *
from microstackshot import *
from xnutriage import *
from kmtriage import *
from kevent import *
from workqueue import *
from ulock import *
from ntstat import *
from zonetriage import *
from sysreg import *
from counter import *
from refgrp import *
from workload import *
from log import showLogStream, show_log_stream_info
from nvram import *
from exclaves import *
from memorystatus import *
from vm_pageout import *
from taskinfo import *
