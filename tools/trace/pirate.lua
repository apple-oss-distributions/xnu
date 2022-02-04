#!/usr/local/bin/recon

local ktrace = require 'ktrace'

if arg[1] == '-h' then
  io.stderr:write[[
usage: pirate [<trace-file-path>]

pirate monitors for jetsam, on the high seas!
]]
  os.exit(0)
end

local sess = ktrace.Session.new(arg[1])

sess:add_callback_pair('MEMSTAT_jetsam', function (start, finish)
  local pid = finish[2]
  local reclaimed_kb = finish[4] / 1024
  local duration_ns = sess:ns_from_abs(finish.abstime - start.abstime)
  print(('%12f: %32s: duration = %gus, reclaimed = %gKB'):format(
      sess:relns_from_abs(start.abstime) / 1e9, sess:procname_for_pid(pid),
      duration_ns / 1000, reclaimed_kb))
end)

local ok, err = sess:start()
if not ok then
  io.stderr:write('pirate: failed to start tracing: ', err, '\n')
  os.exit(1)
end
