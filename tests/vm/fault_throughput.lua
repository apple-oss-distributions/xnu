#!/usr/local/bin/recon

local benchrun = require 'benchrun'
local csv = require 'csv'
local os = require 'os'
local perfdata = require 'perfdata'
local sysctl = require 'sysctl'

require 'strict'

local benchmark = benchrun.new({
  name = 'xnu.zero_fill_fault_throughput',
  version = 1,
  arg = arg,
  modify_argparser = function(parser)
    parser:option{
      name = '--cpu-workers',
      description = 'Number of threads to bring up to do faulting work',
      convert = tonumber,
      argname = 'count',
    }
    parser:flag{
      name = '--through-max-workers',
      description = 'Run with [1..n] CPU workers',
    }
    parser:flag{
      name = '--through-max-workers-fast',
      description = 'Run with 1, 2, and each power of four value in [4..n] CPU workers',
    }
    parser:option{
      name = '--path',
      description = 'Path to fault throughput binary',
      count = 1, -- This is a required option.
    }
    parser:option{
      name = '--duration',
      description = 'How long, in seconds, to run each iteration',
      default = 30,
      convert = tonumber,
      argname = 'seconds',
    }
    parser:option{
      name = '--variant',
      description = 'Which benchmark variant to run',
      choices = { 'separate-objects', 'share-objects' },
      default = 'separate-objects',
      argname = 'name',
    }
    parser:option{
      name = '--first-cpu',
      description = 'Pin threads to CPUs, starting with this CPU ID; requires enable_skstb=1 boot-arg',
      default = -1,
      convert = tonumber,
      argname = 'cpu-id'
    }
    parser:flag{
      name = '--verbose',
      description = 'Enable verbose logging at a performance cost',
    }
  end,
})

local ncpus, _ = sysctl('hw.logicalcpu_max')
benchmark:assert(ncpus > 0, 'invalid number of logical CPUs')
local cpu_workers = benchmark.opt.cpu_workers or ncpus
benchmark:assert(cpu_workers > 0, 'invalid number of CPU workers')

benchmark:assert(benchmark.opt.first_cpu > -2, 'negative first CPU')
benchmark:assert(benchmark.opt.first_cpu < ncpus, 'invalid first CPU')

local page_throughput_unit = perfdata.unit.custom('pages/sec')

local test_threads = {}

if benchmark.opt.through_max_workers then
  for i = 1, cpu_workers do
    table.insert(test_threads, i)
  end
elseif benchmark.opt.through_max_workers_fast then
  local i = 1
  while i <= cpu_workers do
    table.insert(test_threads, i)
    -- Always do a run with two threads to see what the first part of the
    -- scaling curve looks like (and to measure perf on dual core systems).
    if i == 1 and cpu_workers >= 2 then
      table.insert(test_threads, i + 1)
    end
    i = i * 4
  end
else
  table.insert(test_threads, cpu_workers)
end

for _, thread_count in ipairs(test_threads) do
  local cmd = {
    benchmark.opt.path;
    echo = true,
    name = ('with %d CPU workers%s'):format(thread_count,
        thread_count == 1 and '' or 's'),
  }
  if benchmark.opt.verbose then
    cmd[#cmd + 1] = '-v'
  end
  cmd[#cmd + 1] = benchmark.opt.variant
  cmd[#cmd + 1] = benchmark.opt.duration
  cmd[#cmd + 1] = thread_count
  if benchmark.opt.first_cpu ~= -1 then
    cmd[#cmd + 1] = benchmark.opt.first_cpu
  end

  for out in benchmark:run(cmd) do
    local result = out:match('-----Results-----\n(.*)')
    benchmark:assert(result, 'unable to find result data in output')
    local data = csv.openstring(result, { header = true })
    for field in data:lines() do
      for k, v in pairs(field) do
        benchmark.writer:add_value(k, page_throughput_unit, tonumber(v), {
          [perfdata.larger_better] = true,
          threads = thread_count,
          variant = benchmark.opt.variant
        })
      end
    end
  end
end

benchmark:finish()
