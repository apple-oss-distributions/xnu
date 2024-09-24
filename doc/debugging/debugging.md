# XNU debugging

Debugging XNU through kernel core files or with a live device.

## Overview

XNU’s debugging macros are compatible with Python 3.9+. Please be careful about pulling
in the latest language features. Some users are living on older Xcodes and may not have the newest
Python installed.

## General coding tips

### Imports

The current implementation re-exports a lot of submodules through the XNU main module. This leads to some
surprising behavior:

* Name collisions at the top level may override methods with unexpected results.
* New imports may change the order of imports, leading to some surpising side effects.

Please avoid `from xnu import *` where possible and always explicitly import only what is
required from other modules.

### Checking the type of an object

Avoid testing for a `type` explicitly like `type(obj) == type`.
Instead, always use the inheritance-sensitive `isinstance(obj, type)`.

### Dealing with binary data

It’s recommended to use **bytearray**, **bytes**, and **memoryviews** instead of a string.
Some LLDB APIs no longer accept a string in place of binary data in Python 3.

### Accessing large amounts of binary data (or accessing small amounts frequently)

In case you're planning on accessing large contiguous blocks of memory (e.g. reading a whole 10KB of memory),
or you're accessing small semi-contiguous chunks (e.g. if you're parsing large structured data), then it might
be hugely beneficial performance-wise to make use of the `io.SBProcessRawIO` class. Furthermore, if you're in
a hurry and just want to read one specific chunk once, then it might be easier to use `LazyTarget.GetProcess().ReadMemory()`
directly.

In other words, avoid the following:

```
data_ptr = kern.GetValueFromAddress(start_addr, 'uint8_t *')
with open(filepath, 'wb') as f:
    f.write(data_ptr[:4096])
```

And instead use:

```
from core.io import SBProcessRawIO
import shutil

io_access = SBProcessRawIO(LazyTarget.GetProcess(), start_addr, 4096)
with open(filepath, 'wb') as f:
    shutil.copyfileobj(io_access, f)
```

Or, if you're in a hurry:

```
err = lldb.SBError()
my_data = LazyTarget.GetProcess().ReadMemory(start_addr, length, err)
if err.Success():
    # Use my precious data
    pass
```

For small semi-contiguous chunks, you can map the whole region and access random chunks from it like so:

```
from core.io import SBProcessRawIO

io_access = SBProcessRawIO(LazyTarget.GetProcess(), start_addr, size)
io_access.seek(my_struct_offset)
my_struct_contents = io_access.read(my_struct_size)
```

Not only that, but you can also tack on a BufferedRandom class on top of the SBProcessRawIO instance, which
provides you with buffering (aka caching) in case your random small chunk accesses are repeated:

```
from core.io import SBProcessRawIO
from io import BufferedRandom

io_access = SBProcessRawIO(LazyTarget.GetProcess(), start_addr, size)
buffered_io = BufferedRandom(io_access)
# And then use buffered_io for your accesses
```

### Encoding data to strings and back

All strings are now `unicode` and must be converted between binary data and strings explicitly.
When no explicit encoding is selected then UTF-8 is the default.

```
mystring = mybytes.decode()
mybytes = mystring.encode()
```
In most cases **utf-8** will work but be careful to be sure that the encoding matches your data.

There are two options to consider when trying to get a string out of the raw data without knowing if
they are valid string or not:

* **lossy conversion** - escapes all non-standard characters in form of ‘\xNNN’
* **lossless conversion** - maps invalid characters to special unicode range so it can reconstruct
the string precisely

Which to use depends on the transformation goals. The lossy conversion produces a printable string
with strange characters in it. The lossless option is meant to be used when a string is only a transport
mechanism and needs to be converted back to original values later.

Switch the method by using `errors` handler during conversion:

```
# Lossy escapes invalid chars
b.decode('utf-8', errors='`backslashreplace'`)
# Lossy removes invalid chars
b.decode('utf-8', errors='ignore')
# Loss-less but may likely fail to print()
b.decode('utf-8', errors='surrogateescape')
```

### Dealing with signed numbers

Python's int has unlimited precision. This may be surprising for kernel developers who expect
the behavior follows twos complement.

Always use **unsigned()** or **signed()** regardless of what the actual underlying type is
to ensure that macros use the correct semantics.

## Testing changes

Please check documentation here: <doc:macro_testing>

### Coding style

Use a static analyzer like **pylint** or **flake8** to check the macro source code:

```
$ python3 -m pip install --user pylint flake8

# Run the lint either by setting your path to point to one of the runtimes
# or through python
$ python3 -m pylint <src files/dirs>
$ python3 -m flake8 <src files/dirs>
```

### Correctness

Ensure the macro matches what LLDB returns from the REPL. For example, compare `showproc(xxx)` with `p/x *(proc_t)xxx`.

```
# 1. Run LLDB with debug options set
$ DEBUG_XNU_LLDBMACROS=1 xcrun -sdk <sdk> lldb -c core <dsympath>/mach_kernel

# 2. Optionally load modified operating system plugin
(lldb) settings set target.process.python-os-plugin-path <srcpath>/tools/lldbmacros/core/operating_system.py

# 3. Load modified scripts
(lldb) command script import <srcpath>/tools/lldbmacros/xnu.py

# 4. Exercise macros
```

Depending on the change, test other targets and architectures (for instance, both Astris and KDP).

### Regression

This is simpler than previous step because the goal is to ensure behavior has not changed.
You can speed up few things by using local symbols:

```
# 1. Get a coredump from a device and kernel UUID
# 2. Grab symbols with dsymForUUID
$ dsymForUUID --nocache --copyExecutable --copyDestination <dsym path>

# 3. Run lldb with local symbols to avoid dsymForUUID NFS

$ xcrun -sdk <sdk> lldb -c core <dsym_path>/<kernel image>
```

The actual steps are identical to previous testing. Run of a macro to different file with `-o <outfile>`
option. Then run `diff` on the outputs of the baseline and modified code:

* No environment variables to get baseline
* Modified dSYM as described above

It’s difficult to make this automated:

* Some macros needs arguments which must be found in a core file.
* Some macros take a long time to run against a target (more than 30 minutes). Instead, a core dump
  should be taken and then inspected afterwards, but this ties up a lab device for the duration of the
  test.
* Even with coredumps, testing the macros takes too long in our automation system and triggers the
  failsafe timeout.

### Code coverage

Use code coverage to check which parts of macros have actually been tested.
Install **coverage** lib with:

```
$ python3 -m pip install --user coverage
```

Then collect coverage:.

```
(lldb) xnudebug coverage /tmp/coverage.cov showallstacks

...

Coverage info saved to: "/tmp/coverage.cov"
```

You can then run `coverage html --data-file=/tmp/coverage.cov` in your terminal
to generate an HTML report.


Combine coverage from multiple files:

```
# Point PATH to local python where coverage is installed.
$ export PATH="$HOME/Library/Python/3.8/bin:$PATH"

# Use --keep to avoid deletion of input files after merge.
$ coverage combine --keep <list of .coverage files or dirs to scan>

# Get HTML report or use other subcommands to inspect.
$ coverage html
```

It is possible to start coverage collection **before** importing the operating system library and
loading macros to check code run during bootstrapping.

For this, you'll need to run coverage manually:
# 1. Start LLDB

# 2. Load and start code coverage recording.
(lldb) script import coverage
(lldb) script cov = coverage.Coverage(data_file=_filepath_)
(lldb) script cov.start()

# 3. Load macros

# 4. Collect the coverage.
(lldb) script cov.stop()
(lldb) script cov.save()

### Performance testing

Some macros can run for a long time. Some code may be costly even if it looks simple because objects
aren’t cached or too many temporary objects are created. Simple profiling is similar to collecting
code coverage.

First setup your environment:

```
# Install gprof2dot
$ python3 -m pip install gprof2dot
# Install graphviz
$ brew install graphviz
```

Then to profile commands, follow this sequence:

```
(lldb) xnudebug profile /tmp/macro.prof showcurrentstacks
[... command outputs ...]

   Ordered by: cumulative time
   List reduced from 468 to 30 due to restriction <30>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   [... profiling output ...]

Profile info saved to "/tmp/macro.prof"
```

Then to visualize callgraphs in context, in a separate shell:

```
# Now convert the file to a colored SVG call graph
$ python3 -m gprof2dot -f pstats /tmp/macro.prof -o /tmp/call.dot
$ dot -O -T svg /tmp/call.dot

# and view it in your favourite viewer
$ open /tmp/call.dot.svg
```

## Debugging your changes

### Get detailed exception report

The easiest way to debug an exception is to re-run your macro with the `--debug` option.
This turns on more detailed output for each stack frame that includes source lines
and local variables.

### File a radar

To report an actionable radar, please use re-run your failing macro with `--radar`.
This will collect additional logs to an archive located in `/tmp`.

Use the link provided to create a new radar.

### Debugging with pdb

YES, It is possible to use a debugger to debug your macro!

The steps are similar to testing techniques described above (use scripting interactive mode). There is no point to
document the debugger itself. Lets focus on how to use it on a real life example. The debugger used here is PDB which
is part of Python installation so works out of the box.

Problem: Something wrong is going on with addkext macro. What now?

    (lldb) addkext -N com.apple.driver.AppleT8103PCIeC
    Failed to read MachO for address 18446741875027613136 errormessage: seek to offset 2169512 is outside window [0, 1310]
    Failed to read MachO for address 18446741875033537424 errormessage: seek to offset 8093880 is outside window [0, 1536]
    Failed to read MachO for address 18446741875033568304 errormessage: seek to offset 8124208 is outside window [0, 1536]
	...
	Fetching dSYM for 049b9a29-2efc-32c0-8a7f-5f29c12b870c
    Adding dSYM (049b9a29-2efc-32c0-8a7f-5f29c12b870c) for /Library/Caches/com.apple.bni.symbols/bursar.apple.com/dsyms/StarE/AppleEmbeddedPCIE/AppleEmbeddedPCIE-502.100.35~3/049B9A29-2EFC-32C0-8A7F-5F29C12B870C/AppleT8103PCIeC
    section '__TEXT' loaded at 0xfffffe001478c780

There is no exception, lot of errors and no output. So what next?
Try to narrow the problem down to an isolated piece of macro code:

  1. Try to get values of globals through regular LLDB commands
  2. Use interactive mode and invoke functions with arguments directly.

After inspecting addkext macro code and calling few functions with arguments directly we can see that there is an
exception in the end. It was just captured in try/catch block. So the simplified reproducer is:

    (lldb) script
    >>> import lldb
    >>> import xnu
    >>> err = lldb.SBError()
    >>> data = xnu.LazyTarget.GetProcess().ReadMemory(0xfffffe0014c0f3f0, 0x000000000001b5d0, err)
    >>> m = macho.MemMacho(data, len(data))
    Traceback (most recent call last):
      File "<console>", line 1, in <module>
      File ".../lldbmacros/macho.py", line 91, in __init__
        self.load(fp)
      File ".../site-packages/macholib/MachO.py", line 133, in load
        self.load_header(fh, 0, size)
      File ".../site-packages/macholib/MachO.py", line 168, in load_header
        hdr = MachOHeader(self, fh, offset, size, magic, hdr, endian)
      File ".../site-packages/macholib/MachO.py", line 209, in __init__
        self.load(fh)
      File ".../lldbmacros/macho.py", line 23, in new_load
        _old_MachOHeader_load(s, fh)
      File ".../site-packages/macholib/MachO.py", line 287, in load
        fh.seek(seg.offset)
      File ".../site-packages/macholib/util.py", line 91, in seek
        self._checkwindow(seekto, "seek")
      File ".../site-packages/macholib/util.py", line 76, in _checkwindow
        raise IOError(
    OSError: seek to offset 9042440 is outside window [0, 112080]

Clearly an external library is involved and execution flow jumps between dSYM and the library few times.
Lets try to look around with a debugger.

    (lldb) script
	# Prepare data variable as described above.

	# Run last statement with debugger.
	>>> import pdb
	>>> pdb.run('m = macho.MemMacho(data, len(data))', globals(), locals())
	> <string>(1)<module>()

	# Show debugger's help
	(Pdb) help

It is not possible to break on exception. Python uses them a lot so it is better to put a breakpoint to source
code. This puts breakpoint on the IOError exception mentioned above.

	(Pdb) break ~/Library/Python/3.8/lib/python/site-packages/macholib/util.py:76
    Breakpoint 4 at ~/Library/Python/3.8/lib/python/site-packages/macholib/util.py:76

You can now single step or continue the execution as usuall for a debugger.

    (Pdb) cont
    > /Users/tjedlicka/Library/Python/3.8/lib/python/site-packages/macholib/util.py(76)_checkwindow()
    -> raise IOError(
    (Pdb) bt
      /Volumes/.../Python3.framework/Versions/3.8/lib/python3.8/bdb.py(580)run()
    -> exec(cmd, globals, locals)
      <string>(1)<module>()
      /Volumes/...dSYM/Contents/Resources/Python/lldbmacros/macho.py(91)__init__()
    -> self.load(fp)
      /Users/.../Library/Python/3.8/lib/python/site-packages/macholib/MachO.py(133)load()
    -> self.load_header(fh, 0, size)
      /Users/.../Library/Python/3.8/lib/python/site-packages/macholib/MachO.py(168)load_header()
    -> hdr = MachOHeader(self, fh, offset, size, magic, hdr, endian)
      /Users/.../Library/Python/3.8/lib/python/site-packages/macholib/MachO.py(209)__init__()
    -> self.load(fh)
      /Volumes/...dSYM/Contents/Resources/Python/lldbmacros/macho.py(23)new_load()
    -> _old_MachOHeader_load(s, fh)
      /Users/.../Library/Python/3.8/lib/python/site-packages/macholib/MachO.py(287)load()
    -> fh.seek(seg.offset)
      /Users/.../Library/Python/3.8/lib/python/site-packages/macholib/util.py(91)seek()
    -> self._checkwindow(seekto, "seek")
    > /Users/.../Library/Python/3.8/lib/python/site-packages/macholib/util.py(76)_checkwindow()
    -> raise IOError(


Now we can move a frame above and inspect stopped target:

    # Show current frame arguments
    (Pdb) up
    (Pdb) a
    self = <fileview [0, 112080] <macho.MemFile object at 0x1075cafd0>>
    offset = 9042440
    whence = 0

    # globals, local or expressons
    (Pdb) p type(seg.offset)
    <class 'macholib.ptypes.p_uint32'>
    (Pdb) p hex(seg.offset)
    '0x89fa08'

    # Find attributes of a Python object.
    (Pdb) p dir(section_cls)
    ['__class__', '__cmp__', ... ,'reserved3', 'sectname', 'segname', 'size', 'to_fileobj', 'to_mmap', 'to_str']
    (Pdb) p section_cls.sectname
    <property object at 0x1077bbef0>

Unfortunately everything looks correct but there is actually one ineteresting frame in the stack. The one which
provides the offset to the seek method. Lets see where we are in the source code.

    (Pdb) up
    > /Users/tjedlicka/Library/Python/3.8/lib/python/site-packages/macholib/MachO.py(287)load()
    -> fh.seek(seg.offset)
    (Pdb) list
    282  	                        not_zerofill = (seg.flags & S_ZEROFILL) != S_ZEROFILL
    283  	                        if seg.offset > 0 and seg.size > 0 and not_zerofill:
    284  	                            low_offset = min(low_offset, seg.offset)
    285  	                        if not_zerofill:
    286  	                            c = fh.tell()
    287  ->	                            fh.seek(seg.offset)
    288  	                            sd = fh.read(seg.size)
    289  	                            seg.add_section_data(sd)
    290  	                            fh.seek(c)
    291  	                        segs.append(seg)
    292  	                # data is a list of segments

Running debugger on working case and stepping through the load() method shows that this code is not present.
That means we are broken by a library update! Older versions of library do not load data for a section.
