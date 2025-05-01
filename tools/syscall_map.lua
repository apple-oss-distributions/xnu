#!/usr/bin/env recon

local cjson = require 'cjson'
local lpeg = require 'lpeg'
lpeg.locale(lpeg)

-- Only certain regions of the master file should be parsed.
-- The convention is that any `#if/#else/#endif` clauses are parsed, assuming the condition is true/defined, except for `COMPAT_GETFSSTAT`.

local region_state = { valid = true, }
local function in_valid_region(line)
  -- Only C preprocessor directives can affect the region's validity.
  if line:sub(1, 1) ~= '#' then
    return region_state.valid
  end

  -- This is the only macro definition that is assumed to be undefined.
  local assume_defined = not line:match('COMPAT_GETFSSTAT')
  if line:match('^#if') then
    region_state.valid = assume_defined
  elseif line:match('^#else') then
    region_state.valid = not region_state.valid
  elseif line:match('^#endif') then
    region_state.valid = true
  end
end

-- Parse a syscall declaration line from `bsd/kern/syscalls.master` into a table with `name`, `number`, `arguments`, and `old` keys.

-- Primitive tokens.
local space = lpeg.S(' \t')^0
local identifier = (lpeg.alnum + lpeg.P('_'))^1
local numeric = lpeg.digit^1 / tonumber

-- Matching the function name of the syscall declaration.
local function_ptn = lpeg.Cg(identifier^1, 'name') * lpeg.P('(')
local nosys_ptn = lpeg.P('e')^-1 * lpeg.P('nosys(')

-- Matching an argument list.
local arg = lpeg.C((1 - lpeg.S(',)'))^1)
local args_ptn = lpeg.Ct(arg * (lpeg.P(',') * space * arg)^0)

-- Matching a normal C-style declaration of the syscall.
local decl_ptn = (1 - function_ptn)^1 * (function_ptn - nosys_ptn) *
    lpeg.Cg(args_ptn, 'arguments')

-- Matching an old breadcrumb, with empty arguments table.
local old_ptn = lpeg.P('old') * space * lpeg.Cg(identifier^1, 'name') *
    lpeg.Cg(lpeg.Cc(true), 'old') * lpeg.Cg(lpeg.Cc({}), 'arguments')
local old_decl_ptn = (1 - old_ptn)^1 * old_ptn

local syscall_ptn = lpeg.Ct(lpeg.Cg(numeric, 'number') *
    (decl_ptn + old_decl_ptn))

local bsd_syscalls = {}
for line in io.stdin:lines() do
  if in_valid_region(line) then
    bsd_syscalls[#bsd_syscalls + 1] = syscall_ptn:match(line)
  end
end

local syscalls = {
  bsd_syscalls = bsd_syscalls,
  mach_syscalls = {
    -- Duplicate the names from `mach_trap_table` here.
    { number = 10, name = 'mach_vm_allocate',
      arguments = {
        'mach_port_name_t target',
        'mach_vm_address_t *address',
        'mach_vm_size_t size',
        'int flags',
      },
    },
    { number = 11, name = 'mach_vm_purgable_control',
      arguments = {
        'mach_port_name_t target',
        'mach_vm_offset_t address',
        'vm_purgable_t control',
        'int *state',
      },
    },
    { number = 12, name = 'mach_vm_deallocate',
      arguments = {
        'mach_port_name_t target',
        'mach_vm_address_t address',
        'mach_vm_size_t size',
      },
    },
    { number = 13, name = 'task_dyld_process_info_notify_get',
      arguments = {
        'mach_port_name_array_t names_addr',
        'natural_t *names_count_addr',
      },
    },
    { number = 14, name = 'mach_vm_protect',
      arguments = {
        'mach_port_name_t task',
        'mach_vm_address_t address',
        'mach_vm_size_t size',
        'boolean_t set_maximum',
        'vm_prot_t new_protection',
      }
    },
    { number = 15, name = 'mach_vm_map',
      arguments = {
        'mach_port_name_t target',
        'mach_vm_address_t *address',
        'mach_vm_size_t size',
        'mach_vm_offset_t mask',
        'int flags',
        'mem_entry_name_port_t object',
        'memory_object_offset_t offset',
        'boolean_t copy',
        'vm_prot_t cur_protection',
        'vm_prot_t max_protection',
        'vm_inherit_t inheritance',
      },
    },
    { number = 16, name = 'mach_port_allocate',
      arguments = {
        'mach_port_name_t target',
        'mach_port_right_t right',
        'mach_port_name_t *name',
      },
    },

    { number = 18, name = 'mach_port_deallocate',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
      },
    },
    { number = 19, name = 'mach_port_mod_refs',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'mach_port_right_t right',
        'mach_port_delta_t delta',
      },
    },
    { number = 20, name = 'mach_port_move_member',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t member',
        'mach_port_name_t after',
      },
    },
    { number = 21, name = 'mach_port_insert_right',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'mach_port_name_t poly',
        'mach_msg_type_name_t polyPoly',
      },
    },
    { number = 22, name = 'mach_port_insert_member',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'mach_port_name_t pset',
      },
    },
    { number = 23, name = 'mach_port_extract_member',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'mach_port_name_t pset',
      },
    },
    { number = 24, name = 'mach_port_construct',
      arguments = {
        'mach_port_name_t target',
        'mach_port_options_t *options',
        'uint64_t context',
        'mach_port_name_t *name',
      },
    },
    { number = 25, name = 'mach_port_destruct',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'mach_port_delta_t srdelta',
        'uint64_t guard',
      },
    },
    { number = 26, name = 'mach_reply_port',
      arguments = { 'void' },
    },
    { number = 27, name = 'thread_self',
      arguments = { 'void' },
    },
    { number = 28, name = 'task_self',
      arguments = { 'void' },
    },
    { number = 29, name = 'host_self',
      arguments = { 'void' },
    },

    { number = 31, name = 'mach_msg',
      arguments = {
        'mach_msg_header_t *msg',
        'mach_msg_option_t option',
        'mach_msg_size_t send_size',
        'mach_msg_size_t rcv_size',
        'mach_port_name_t rcv_name',
        'mach_msg_timeout_t timeout',
        'mach_port_name_t notify',
      },
    },
    { number = 32, name = 'mach_msg_overwrite',
      arguments = {
        'mach_msg_header_t *msg',
        'mach_msg_option_t option',
        'mach_msg_size_t send_size',
        'mach_msg_size_t rcv_size',
        'mach_port_name_t rcv_name',
        'mach_msg_timeout_t timeout',
        'mach_port_name_t notify',
        'mach_msg_header_t *rcv_msg',
        'mach_msg_size_t rcv_limit',
      },
    },
    { number = 33, name = 'semaphore_signal',
      arguments = {
        'mach_port_name_t signal_name',
      },
    },
    { number = 34, name = 'semaphore_signal_all',
      arguments = {
        'mach_port_name_t signal_name',
      },
    },
    { number = 35, name = 'semaphore_signal_thread',
      arguments = {
        'mach_port_name_t signal_name',
        'mach_port_name_t thread_name',
      },
    },
    { number = 36, name = 'semaphore_wait',
      arguments = {
        'mach_port_name_t wait_name',
      },
    },
    { number = 37, name = 'semaphore_wait_signal',
      arguments = {
        'mach_port_name_t wait_name',
        'mach_port_name_t signal_name',
      },
    },
    { number = 38, name = 'semaphore_timedwait',
      arguments = {
        'mach_port_name_t wait_name',
        'unsigned int sec',
        'clock_res_t nsec',
      },
    },
    { number = 39, name = 'semaphore_timedwait_signal',
      arguments = {
        'mach_port_name_t wait_name',
        'mach_port_name_t signal_name',
        'unsigned int sec',
        'clock_res_t nsec',
      },
    },
    { number = 40, name = 'mach_port_get_attributes',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'mach_port_flavor_t flavor',
        'mach_port_info_t port_info_out',
        'mach_msg_type_number_t *port_info_outCnt',
      },
    },
    { number = 41, name = 'mach_port_guard',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'uint64_t guard',
        'boolean_t strict',
      },
    },
    { number = 42, name = 'mach_port_unguard',
      arguments = {
        'mach_port_name_t target',
        'mach_port_name_t name',
        'uint64_t guard',
      },
    },
    { number = 43, name = 'mach_generate_activity_id',
      arguments = {
        'mach_port_name_t target',
        'int count',
        'uint64_t *activity_id',
      },
    },
    { number = 44, name = 'task_name_for_pid',
      arguments = {
        'mach_port_name_t target_tport',
        'int pid',
        'mach_port_name_t *tn',
      },
    },
    { number = 45, name = 'task_for_pid',
      arguments = {
        'mach_port_name_t target_tport',
        'int pid',
        'mach_port_name_t *t',
      },
    },
    { number = 46, name = 'pid_for_task',
      arguments = {
        'mach_port_name_t t',
        'int *x',
      },
    },
    { number = 47, name = 'mach_msg2',
      arguments = {
        'void *data',
        'mach_msg_option64_t option64',
        'mach_msg_header_t header',
        'mach_msg_size_t send_size',
        'mach_msg_size_t rcv_size',
        'mach_port_t rcv_name',
        'uint64_t timeout',
        'uint32_t priority',
      },
    },
    { number = 48, name = 'macx_swapon',
      arguments = {
        'uint64_t filename',
        'int flags',
        'int size',
        'int priority',
      },
    },
    { number = 49, name = 'macx_swapoff',
      arguments = {
        'uint64_t filename',
        'int flags',
      },
    },
    { number = 50, name = 'thread_get_special_reply_port',
      arguments = { 'void' },
    },
    { number = 51, name = 'macx_triggers',
      arguments = {
        'int hi_water',
        'int low_water',
        'int flags',
        'mach_port_t alert_port',
      },
    },
    { number = 52, name = 'macx_backing_store_suspend',
      arguments = {
        'boolean_t suspend',
      },
    },
    { number = 53, name = 'macx_backing_store_recovery',
      arguments = {
        'int pid',
      },
    },

    { number = 58, name = 'pfz_exit',
      arguments = { 'void' },
    },
    { number = 59, name = 'swtch_pri',
      arguments = {
        'int pri',
      },
    },
    { number = 60, name = 'swtch',
      arguments = { 'void' },
    },
    { number = 61, name = 'thread_switch',
      arguments = {
        'mach_port_name_t thread_name',
        'int option',
        'mach_msg_timeout_t option_time',
      },
    },
    { number = 62, name = 'clock_sleep',
      arguments = {
        'mach_port_name_t clock_name',
        'sleep_type_t sleep_type',
        'int sleep_sec',
        'int sleep_nsec',
        'mach_timespec_t *wakeup_time',
      },
    },

    { number = 70, name = 'host_create_mach_voucher',
      arguments = {
        'mach_port_name_t host',
        'mach_voucher_attr_raw_recipe_array_t recipes',
        'int recipes_size',
        'mach_port_name_t *voucher',
      },
    },

    { number = 72, name = 'mach_voucher_extract_attr_recipe',
      arguments = {
        'mach_port_name_t voucher_name',
        'mach_voucher_attr_key_t key',
        'mach_voucher_attr_raw_recipe_t recipe',
        'mach_msg_type_number_t *recipe_size',
      },
    },

    { number = 76, name = 'mach_port_type',
      arguments = {
        'ipc_space_t task',
        'mach_port_name_t name',
        'mach_port_type_t *ptype',
      },
    },
    { number = 77, name = 'mach_port_request_notification',
      arguments = {
        'ipc_space_t task',
        'mach_port_name_t name',
        'mach_msg_id_t msgid',
        'mach_port_mscount_t sync',
        'mach_port_name_t notify',
        'mach_msg_type_name_t notifyPoly',
        'mach_port_name_t *previous',
      },
    },
    { number = 88, name = 'exclaves_ctl',
      arguments = {
        'mach_port_name_t name',
        'uint32_t operation_and_flags',
        'uint64_t identifier',
        'mach_vm_address_t buffer',
        'mach_vm_size_t size',
        'mach_vm_size_t size2',
        'mach_vm_size_t offset',
        'mach_vm_address_t status',
      },
    },

    { number = 89, name = 'mach_timebase_info',
      arguments = {
        'mach_timebase_info_t info',
      },
    },
    { number = 90, name = 'mach_wait_until',
      arguments = {
        'uint64_t deadline',
      },
    },
    { number = 91, name = 'mk_timer_create',
      arguments = { 'void' },
    },
    { number = 92, name = 'mk_timer_destroy',
      arguments = {
        'mach_port_name_t name',
      },
    },
    { number = 93, name = 'mk_timer_arm',
      arguments = {
        'mach_port_name_t name',
        'uint64_t expire_time',
      },
    },
    { number = 94, name = 'mk_timer_cancel',
      arguments = {
        'mach_port_name_t name',
        'uint64_t *result_time',
      },
    },
    { number = 95, name = 'mk_timer_arm_leeway',
      arguments = {
        'mach_port_name_t name',
        'uint64_t mk_timer_flags',
        'uint64_t mk_timer_expire_time',
        'uint64_t mk_timer_leeway',
      },
    },
    { number = 96, name = 'debug_control_port_for_pid',
      arguments = {
        'mach_port_name_t target_tport',
        'int pid',
        'mach_port_name_t *t',
      },
    },

    { number = 100, name = 'iokit_user_client',
      arguments = {
        'void *userClientRef',
        'uint32_t index',
        'void *p1',
        'void *p2',
        'void *p3',
        'void *p4',
        'void *p5',
        'void *p6',
      },
    },
  },
}

-- Basic sanity checking that the same number isn't claimed by two syscalls.
for type, entries in pairs(syscalls) do
  local numbers_seen = {}
  for _, call in ipairs(entries) do
    if numbers_seen[call.number] then
      io.stderr:write(('error: %s: saw %d twice: %s and %s\n'):format(type,
          call.number, call.name, numbers_seen[call.number]))
      os.exit(1)
    end
    numbers_seen[call.number] = call.name
  end
end

print(cjson.encode(syscalls))
