from ioreg import *

@lldb_command("shownvram")
def PrintNvramVars(cmd_args=[]):
    """
    Print NVRAM variables.
    """
    dt_plane = GetRegistryPlane("IODeviceTree")
    if dt_plane is None:
        raise ValueError("Couldn't obtain a pointer to IODeviceTree")

    # Registry API functions operate on "plane" global variable
    global plane
    prev_plane = plane
    plane = dt_plane
    options = FindRegistryObjectRecurse(kern.globals.gRegistryRoot, "options")
    # Restore original plane after getting options
    plane = prev_plane
    if options is None:
        print("Couldn't obtain options IORegistryEntry")
        return

    nvram_diags = kern.GetValueFromAddress('((IODTNVRAM *)' + hex(options) + ')->_diags', 'IOService *')
    nvram_vers = LookupKeyInPropTable(nvram_diags.fPropertyTable, "Version")

    if (GetNumber(nvram_vers) == "3"):
        var_dict = kern.GetValueFromAddress('((IONVRAMV3Handler *)((IODTNVRAM *)' + hex(options) + ')->_format)->_varDict.ptr_', 'OSDictionary *')
    else:
        var_dict = kern.GetValueFromAddress('((IONVRAMCHRPHandler *)((IODTNVRAM *)' + hex(options) + ')->_format)->_varDict.ptr_', 'OSDictionary *')

    if var_dict is None:
        print("Couldn't obtain varDict")
        return

    for x in range(var_dict.count):
        name = var_dict.dictionary[x].key.string
        value = var_dict.dictionary[x].value

        # get value type
        value_info = GetObjectTypeStr(value)
        if value_info is None:
            print("Couldn't obtain object type for name:", name, "value:", value)
            continue
        srch = re.search(r'vtable for ([A-Za-z].*)', value_info)
        if not srch:
            print("Couldn't find type in value_info:", value_info)
            continue
        value_type = srch.group(1)

        if (value_type == 'OSString'):
            print(name, '=', GetString(value))
        elif (value_type == 'OSData'):
            data_ptr = Cast(value.data, 'uint8_t *')
            print (name, '= ', end ='')
            data_buffer = ""
            for i in range(value.length):
                if ((data_ptr[i] >= 0x20 and data_ptr[i] <= 0x7e) and chr(data_ptr[i]) != '%'):
                    data_buffer += chr(data_ptr[i])
                else:
                    data_buffer += "%%%02x" % data_ptr[i]
            print (data_buffer)
        elif (value_type == 'OSNumber'):
            print(name, '=', GetNumber(value))
        elif (value_type == 'OSBoolean'):
            print(name, '=', GetBoolean(value))
        else:
            print("Invalid type:", value_type)