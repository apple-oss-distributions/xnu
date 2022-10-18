#!/usr/local/bin/recon

local benchrun = require 'benchrun'
local perfdata = require 'perfdata'
local csv = require 'csv'
local sysctl = require 'sysctl'

require 'strict'

local kDefaultDuration = 15 

local benchmark = benchrun.new {
    name = 'xnu.perf_compressor',
    version = 1,
    arg = arg,
    modify_argparser = function(parser)
        parser:argument {
          name = 'path',
          description = 'Path to perf_compressor binary'
        }
        parser:option{
          name = '--duration',
          description = 'How long, in seconds, to run each iteration',
          default = kDefaultDuration
        }
        parser:option{
            name = '--variant',
            description = 'Which benchmark variant to run',
            default = 'compress-and-decompress',
            choices = {'compress', 'compress-and-decompress'}
        }
        parser:option{
            name = '--buffer-size',
            description = 'MB size of buffer to send to compressor',
            default = 100
        }
        parser:option{
            name = '--data-type',
            description = 'Fill the buffer with random, zero, or typical data',
            default = 'typical',
            choices = {'typical', 'random', 'zero'}
        }
        parser:flag {
            name = '--verbose',
            description = 'Print benchmark progress',
        }
    end
}
local is_development_kernel, err = sysctl("kern.development")
benchmark:assert(err == nil, "Unable to check for development kernel")
if is_development_kernel == 0 then
    print "Skipping benchmark on non-development kernel."
    os.exit(0)
end
local hw_page_size, err = sysctl("hw.pagesize")
benchmark:assert(err == nil, "Unable to check hw page size")
local vm_page_size, err = sysctl("vm.pagesize")
benchmark:assert(err == nil, "Unable to check vm page size")
if hw_page_size ~= vm_page_size then
    print "Skipping benchmark on this platform because benchmark process has a different page size than the kernel"
    os.exit(0)
end

args = {benchmark.opt.path, benchmark.opt.variant, benchmark.opt.data_type, benchmark.opt.duration, benchmark.opt.buffer_size}
if benchmark.opt.verbose then
    table.insert(args, 2, "-v")
    args["echo"] = true
end
for out in benchmark:run(args) do
    local result = out:match("-----Results-----\n(.*)")
    benchmark:assert(result, "Unable to find result data in output")
    local data = csv.openstring(result, {header = true})
    for field in data:lines() do
        for k, v in pairs(field) do
            unit = perfdata.unit.bytes_per_second
            if k == "Compression Ratio" then
                unit = perfdata.unit.custom("uncompressed / compressed")
            end
            benchmark.writer:add_value(k, unit, tonumber(v), {
                data_type = benchmark.opt.data_type,
                buffer_size = benchmark.opt.buffer_size,
                [perfdata.larger_better] = true
            })
        end
    end
end

benchmark:finish()
