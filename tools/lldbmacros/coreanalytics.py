from xnu import *

@lldb_command("showcoreanalyticsformatstr")
def PrintCoreAnalyticsFormatStr(cmd_args=None):
    """ Pretty prints the full format string for a core analyics event
        Usage: showcoreanalyticsformatstr <event>
    """
    if cmd_args is None or len(cmd_args) == 0:
        raise ArgumentError("Please specify an event.")

    #event_ptr = kern.GetValueFromAddress(cmd_args[0], "struct _ca_event *").GetSBValue().GetValueAsUnsigned()
    #print(event_ptr)
    event = kern.GetValueFromAddress(cmd_args[0], "struct _ca_event *")
    event_name = str(event.format_str)
    print(event_name)
    curr = event.format_str.GetSBValue().GetValueAsUnsigned()
    offset = len(event_name) + 1
    while True:
        val = kern.GetValueFromAddress(curr + offset, "char *")
        as_string = str(val)
        if len(as_string) == 0:
            break
        offset = offset + len(as_string) + 1
        print(as_string)
