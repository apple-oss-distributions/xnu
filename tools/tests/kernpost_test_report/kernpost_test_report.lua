#!/usr/local/bin/recon

local argparse = require 'argparse'
local darwin = require 'darwin'
local plist = require 'plist'
local kcdata = require 'kcdata'
local lfs = require 'lfs'
local sysctl = require 'sysctl'

require 'strict'

local parser = argparse(){
  name = 'kernpost_report',
}

local FMT_RAW <const> = 'raw'
local FMT_PLIST <const> = 'plist'
local FMT_BUNDLE <const> = 'resultbundle'

local export = parser:command('export')
export:option{
  name = '-f --format',
  description = 'the format to export the tests in',
  choices = { FMT_RAW, FMT_PLIST, FMT_BUNDLE, },
  count = '?',
}
export:option{
  name = '-o --output',
  description = 'where to write the report, must be a directory',
  count = 1,
}

local function write_file(path, data)
  local f, err = io.open(path, 'w')
  if not f then
    io.stderr:write(path, ': failed to open for writing: ', err, '\n')
    os.exit(1)
  end
  f:write(data)
  f:close()
end

local function default_test_info(config)
  return {
    version = 2,
    test_category = 'unittest',
    Project = 'xnu',
    ['boot-args'] = assert(config.boot_args),
    osVersion = assert(config.osversion),
    mach_timebase_info = config.mach_timebase_info,
  }
end

local function current_timezone_offset()
  local now = os.time()
  local timezone = os.difftime(now, os.time(os.date("!*t", now)))
  local h, m = math.modf(timezone / 3600)
  return ("%+.2d:%.2d"):format(h, 60 * m)
end
local timezone_offset = current_timezone_offset()

local function convert_time(raw_time, tb)
  local time_secs = raw_time * tb.numer / tb.denom / 1e9
  local boottime_secs = darwin.mach_boottime_usec() / 1e6
  local walltime_secs = math.modf(boottime_secs + time_secs)
  local time_str = os.date('%Y-%m-%dT%H:%M:%S', walltime_secs)
  local time_ms_str = time_str .. '.' .. tostring(
      math.floor(walltime_secs / 1e6))
  return time_ms_str .. timezone_offset
end

local function write_test_result(config, test_data, dir)
  local info_tbl = default_test_info(config)

  local name = test_data.test_name
  local test_dir = dir .. '/test_' .. name
  lfs.mkdir(test_dir)

  info_tbl.test_id = name

  local test_pass = test_data.retval ~= nil and
      test_data.retval == test_data.expected_retval
  info_tbl.result_code = test_pass and 200 or 400

  local tb = config.mach_timebase_info
  info_tbl.result_started = convert_time(test_data.begin_time, tb)
  info_tbl.beginTimeRaw = test_data.begin_time

  info_tbl.result_finished = convert_time(test_data.end_time, tb)
  info_tbl.endTimeRaw = test_data.end_time

  local info_path <const> = test_dir .. '/Info.plist'
  local info_plist, err = plist.encode(info_tbl)
  if not info_plist then
    io.stderr:write('error: failed to serialize test Info.plist: ', err, '\n')
    os.exit(1)
  end
  write_file(info_path, info_plist)

  lfs.mkdir(test_dir .. '/Attachments')
  lfs.mkdir(test_dir .. '/Diagnostics')

  local status_path = test_dir .. '/' .. (test_pass and 'PASS' or 'FAIL') ..
      '.status'
  write_file(status_path, '')
end

local function write_result_bundle(data, dir)
  lfs.mkdir(dir)
  local config = data.xnupost_testconfig
  for _, test in ipairs(config.xnupost_test_config) do
    write_test_result(config, test, dir)
  end
end

export:action(function (args)
  local dir = args.output
  if lfs.attributes(dir, 'mode') ~= 'directory' then
    io.stderr:write(dir, ': output path must be a directory\n')
    os.exit(1)
  end

  local raw_data, err = sysctl('debug.xnupost_get_tests')
  if not raw_data then
    io.stderr:write('error: failed to retrieve test data from kernel: ', err,
        '\n')
    os.exit(1)
  end

  if args.format == FMT_RAW then
    write_file(dir .. '/xnupost.kcdata', raw_data)
  elseif args.format == FMT_PLIST then
    local tbl_data
    tbl_data, err = kcdata.decode(raw_data)
    if not tbl_data then
      io.stderr:write('error: failed to deserialize kernel data: ', err, '\n')
      os.exit(1)
    end
    local data
    data, err = plist.encode(tbl_data, 'xml')
    if not data then
      io.stderr:write('error: failed to serialize kernel data to plist: ', err,
          '\n')
      os.exit(1)
    end
    write_file(dir .. '/xnupost.plist', data)
  elseif args.format == FMT_BUNDLE then
    local tbl_data
    tbl_data, err = kcdata.decode(raw_data)
    if not tbl_data then
      io.stderr:write('error: failed to deserialize kernel data: ', err, '\n')
      os.exit(1)
    end
    write_result_bundle(tbl_data, dir .. '/xnupost')
  end
end)

parser:parse(arg)
