"""
    KernelManagement Triage commands
"""
from xnu import *
import sys, shlex
from utils import *
from ioreg import *
import xnudefines
import os.path

## Symbol names
WAITING_FOR_USER_SERVER_SYMNAME = '__WAITING_FOR_USER_SERVER__'

def GetTokenMemberSafe(token, fn, member):
    try:
        return fn(getattr(token, member))
    except:
        return '<error>'

# Macro: showthreadswaitingforuserserver
@lldb_command('showthreadswaitingforuserserver')
def ShowThreadsWaitingForUserServer(cmd_args=None):
    """ 
    For each task thread that is in __WAITING_FOR_USER_SERVER__,
    prints the thread backtrace, the IOUserServerCheckInToken structure, its server name, and tag.
    Usage: showthreadswaitingforuserserver
    """

    ## Scan threads for interesting information
    for t in kern.tasks:
        for thread_obj in IterateQueue(t.threads, 'thread *', 'task_threads'):
            show_bt = False
            thread_val = GetLLDBThreadForKernelThread(thread_obj)
            for frame in thread_val.frames:
                function = frame.GetFunction()
                if function and frame.GetFunctionName():
                    if frame.GetFunctionName().startswith(WAITING_FOR_USER_SERVER_SYMNAME):
                        show_bt = True
                        arguments = frame.get_arguments()
                        if len(arguments) > 0:
                            token_arg = arguments[0]
                            arg_addr = int(token_arg.value, 0)
                            if arg_addr:
                                token = kern.GetValueFromAddress(arg_addr, 'IOUserServerCheckInToken *')
                               
                                print('fServerName="' + GetTokenMemberSafe(token, GetString, 'fServerName') + '"')
                                print('fExecutableName="' + GetTokenMemberSafe(token, GetString, 'fExecutableName') + '"')
                                print('fKextBundleID="' + GetTokenMemberSafe(token, GetString, 'fKextBundleID') + '"')
                                print('fServerTag=' + GetTokenMemberSafe(token, GetNumber, 'fServerTag'))

            ## Show entire thread summary and backtrace
            if show_bt:
                print(GetThreadSummary.header)
                print(GetThreadSummary(thread_obj))
                print(GetThreadBackTrace(thread_obj, prefix="    ") + "\n")
                print('-----\n')
    return
# EndMacro: showthreadswaitingforuserserver
