from memory import IterateZPerCPU
from xnu import (
    LazyTarget, value, ArgumentError,
    lldb_command, lldb_type_summary, header
)


@lldb_type_summary(['scalable_counter_t'])
@header("Counter Value\n-------------")
def GetSimpleCounter(counter):
    """ Prints out the value of a percpu counter
        params: counter: value - value object representing counter
        returns: str - THe value of the counter as a string.
    """
    val = 0
    for v in IterateZPerCPU(counter):
        val += v
    return str(val)

@lldb_command('showcounter')
def ShowSimpleCounter(cmd_args=None):
    """ Show the value of a percpu counter.
        Usage: showcounter <address of counter>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify the address of the "
                            "counter you want to read.")

    val = LazyTarget.GetTarget().chkCreateValueFromExpression(
        'value', f"(scalable_counter_t){cmd_args[0]}")
    print(GetSimpleCounter(value(val)))
