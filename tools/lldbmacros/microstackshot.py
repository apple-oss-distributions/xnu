from xnu import *

@lldb_command('showmicrostackshot', 'O:', fancy=True)
def show_microstackshot(cmd_args=None, cmd_options={}, O=None):
    """
    Show information about the microstackshot subsystem.

    Usage: (lldb) showmicrostackshot [-O <offset>]
    """

    metadata = kern.GetGlobalVariable('telemetry_metadata')
    print('metadata:')
    print('{:>12s}: {}'.format('generation', metadata.tm_generation))
    print('{:>12s}: {}'.format('samples', metadata.tm_samples_recorded))
    print('{:>12s}: {}'.format('skips', metadata.tm_samples_skipped))
    print('{:>12s}: {}'.format('source', metadata.tm_source))
    print('{:>12s}: {}'.format('period', metadata.tm_period))

    kern_ring = kern.GetGlobalVariable("_telemetry_kernel_ring")
    print()
    print('kernel ringbuffer:')
    print('{:>12s}: {}'.format('capacity', kern_ring.mr_capacity))
    print('{:>12s}: {}'.format('head', kern_ring.mr_head_tail.mrht_head))
    print('{:>12s}: {}'.format('tail', kern_ring.mr_head_tail.mrht_tail))
    print('{:>12s}: {}'.format('available', (kern_ring.mr_head_tail.mrht_tail - kern_ring.mr_head_tail.mrht_head) % kern_ring.mr_capacity))

    if kern_ring.mr_head_tail.mrht_tail & 0x3 != 0:
        print('tail is not aligned')
        return

    print()
    print('kernel samples:')
    base_kern_text = kern.GetGlobalVariable('vm_kernel_stext')

    next_record = unsigned(cmd_options.get('-O') or kern_ring.mr_head_tail.mrht_tail)
    print(next_record)
    while (kern_ring.mr_head_tail.mrht_head - next_record) > 0:
        next_record_ptr = kern_ring.mr_buffer + (next_record % kern_ring.mr_capacity)
        next_sample = kern.GetValueFromAddress(next_record_ptr, 'struct _telemetry_kernel_sample *')
        if next_sample.tks_magic != xnudefines.TKS_MAGIC:
            print('magic value for sample at position {} is {}, not {}'.format(
                next_record % kern_ring.mr_capacity, next_sample.tks_magic,
                xnudefines.TKS_MAGIC))
            break
        print('{}.{:09d}: @{} thread 0x{:x} on CPU {}:'.format(next_sample.tks_time_secs,
            next_sample.tks_time_usecs * 1000, next_record, next_sample.tks_thread_id,
            next_sample.tks_cpu))
        call_stack_size = unsigned(next_sample.tks_call_stack_size)
        next_record += sizeof('struct _telemetry_kernel_sample') + call_stack_size
        call_stack = Cast(addressof(next_sample[1]), 'uint32_t *')
        for i in range(call_stack_size // 4):
            if call_stack[i] == 0:
                continue
            addr = base_kern_text + call_stack[i]
            syms = kern.SymbolicateFromAddress(addr)
            name = syms[0].GetName() if syms else '... try showkmodaddr ...'
            print('\t0x{:16x} ({})'.format(addr, name))

    print('end at {}'.format(next_record))
