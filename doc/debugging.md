# XNU debugging

xnu’s debugging macros are compatible with both Python 2 and 3. In practice, this means that Python 3
features are unavailable and some Python 2 syntax is not allowed. Unfortunately, any syntax error will
prevent use of all the macros, as they’re all imported into the same scripting environment.

## Compatibility

Avoid introducing specific compatibility shims, as there are a few existing ones that come with
Python 2 and 3:

* **six** has helpers that work in both Python 2 and 3, for things like the string type change
* **future** backports features from Python 3 to Python 2

For example, Python 2 contains **range** and **xrange**. Python 3 contains only **range** which has
**xrange** semantics. The simplest solution is to port your code and use Python 3 way:

```
# Use backported range from Python 3
from builtins import range

# Use range on both Python 2/3 runtimes
for x in range(....):
   ....
```

Be very careful about using imports from 'future' library. Some of them are **very invasive** and change
behavior of your code. This may cause strange runtime errors. For example:

```
# Changes modules handling logic to make your code working with std library reorg (PEP 3108)
from future import standard_library
standard_library.install_aliases()

# Replaces lot of common types like str with future's Python 3 backports.
from builtins import *
```

## Handling strings

Macros use strings produced from the LLDB runtime. They must use **six** when doing certain operations
to avoid exceptions. Until the transition is done, these canonical ways of dealing with strings cannot
be used:

* Using Unicode literals by default:
   `from __future__ import unicode_literals`
* **f-strings**

Some advice:

* Use byte strings explicitly when dealing with memory and not strings:
  `b'string'`
* Always properly encode/decode raw data to/from strings before passing it around, with `six.ensure_str` or
  `six.ensure_bytes`.

Improperly-typed strings will raise *different* exceptions on each runtime.

* Python 2 raises codec exceptions when printing strings.
* Python 3 complains about concatenation of objects of incompatible types (bytes and strings).

### No convenient, common string type

While it is possible to use future’s **newstr** to backport new string type to Python 3, there are
issues with the Scripting Bridge (SB) API from LLDB. Python 3 will work out of the box but Python 2
will complain because **newstr** maps to **unicode**. SB exposes **const char \*** as a native string,
or just **str** in Python 2. For Python 2 we would have to explicitly encode all Unicode strings
before calling the API.

Another problem is that literals in form `'string'` are no longer compatible with unicode and need
to be switched to `u'string'`. This can be changed with single import at the top of the file, but
in some scenarios byte strings are expected. That change would require checking all strings in the
code and changing some back to  `b'string'`.

Here’s an example of just how pervasive a change would be because this code would break in Python 2:

```
from xnu import *

@lldb_type_summary(['type'])
def print_summary():
   ....
```

The result is that we have non-unicode literal being registered with unicode API in Python 3.
Unfortunately `'type' != b'type'` and thus LLDB will never match the type when printing summaries.

Using native strings and literals allows for only minimal code changes to the macros that are still
compatible with other projects using Python 2.

### Check that an object is a string

Avoid testing for `str` explicitly like `type(obj) == str`. This won’t work correctly as Python 2
has multiple string types (`unicode`, `str`). Additionally, compatibility shims might introduce new
string types.

Instead, always use an inheritance-sensitive like like `isinstance(obj, six.string_types)`.

### Dealing with binary data

Python 2 bytes and strings are the same thing. This was the wrong design decision and Python 3
(wisely) switched to using a separate type for human text. This lack of distinction in Python 2
caused many programming errors, so it’s recommended to use **bytearray**, **bytes**, and
**memoryviews** instead of a string. If a string is really required, encode the raw data explicitly
using an escape method.

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

The simplest solution is to use **six** library and one of the functions like:

```
mystring = six.ensure_str(object)
```

This ensures the resulting value is a native string. It deals with Unicode in Python 2 automatically.
The six library is still required even if data is encoding manually, since it converts types.

```
from builtins import bytes
str = six.ensure_str(bytes.decode('utf-8'))
```

When converting data to a string, add an encoding type so Python knows how handle raw bytes. In most
cases **utf-8** will work but be careful to be sure that the encoding matches your data.

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

## Handling numbers

Numeric types are incompatible between Python 2 and 3:

* **long** is not available in Python 3.
* **int** is the only integral type in Python 3 and hasunlimited precission (but 32-bits in Python 2).

This creates all sorts of issues with macros. Follow these rules to make integral types compatible
in both modes:

* Do not use **long** — replace it with **int**.
* When using the **value** class, types will be promoted to **long** as there is special number
handling in the xnu macro library. Remaining code should be reviewed and fixed, if appropriate.
* Avoid relying on sign extension.
* Always switch Python to use Python 3 division, where `/` converts to floating point and does
a fractional division `//` is a floor division (like integers in C):
   `from __future__ import division
   `
* Use division operators according to Python 3 rules.

### Common integer representation

The goal is to always use Python 3’s integer handling, which means using **int** everywhere.

xnu’s macros provide a custom integer type called **valueint** that is a replacement for **int**
in the Python 2 runtime. That means it behaves almost like **int** from Python 3. When importing
from macros this type replaces any use of **int**:

```
# Replaces all int()s to be valueint
from xnu import *
from xnu import int

# Does not replace int()s
import xnu
from xnu import a, b, c
```

Avoid using `from builtins import int` suggested on the internet. It does not work correctly with
xnu’s **value** class. The **valueint** class inherits from **newint** and fixes problematic behavior.

This impacts the way an object is checked for being an integer. Be careful about following constructs:

```
# BAD: generally not a good way to do type checking in Python
if type(obj) is int:

# BAD: int may have been replaced with valueint.
if isinstance(obj, int):
```

Instead, use the base integral type:

```
if isinstance(obj, numbers.Integral):
```

### Dealing with signed numbers

Original code was using two operators to convert **value** class instance to number:

* **__int__** produced **int** and was either signed or unsigned based on underlying SBType.
* **__long__** was always signed.

This is confusing when dealing with types. Always use **unsigned()** or **signed()** regardless of
what the actual underlying type is to ensure that macros use the correct semantics.

### Dividing numbers

Python 2’s **/** operator has two behaviors depending on the types of its arguments (**float** vs. **int**).
Always use Python 3’s division operator:

```
# Switch compiler to use Python 3 semantics
from __future__ import division

float_val = a / b  # This becomes true, fractional division that yields float
floor_div = a // b # This is floor division, like C
```

If the original behavior is required, use **old_div** to get Python 2 behavior:

```
from past.utils import old_div

value = old_div(a, b)     # Matches Python 2 semantics
```

If this isn’t handled correctly, `format` will complain that a float value is being passed to
a non-float formatting character. Automated scripts that convert from Python 2 to 3 tend to use
**old_div** during porting. In most cases that is not required. For kernel debugging and integer
types, `//` is used commonly to match the C’s division behavior for integers.

## Testing changes

There is no perfect test suite to check that macros are producing a correct value compared to what
the debugger sees in a target.

Be careful when touching common framework code. For larger changes, ask the Platform Triage team to
validate that the changes work in their environment before integration.

### Coding style

Use a static analyzer like **pylint** or **flake8** to check the macro source code:

```
# Python 2
$ pip install --user pylint flake8

# Python 3
$ pip install --user pylint flake8

# Run the lint either by setting your path to point to one of the runtimes
# or through python
$ python2 -m pylint <src files/dirs>
$ python3 -m pylint <src files/dirs>
$ python2 -m flake8 <src files/dirs>
$ python3 -m flake8 <src files/dirs>
```

### Correctness

Ensure the macro matches what LLDB returns from the REPL. For example, compare `showproc(xxx)` with `p/x *(proc_t)xxx`.

```
# 1. Run LLDB with debug options set
$ DEBUG_XNU_LLDBMACROS=1 LLDB_DEFAULT_PYTHON_VERSION=2 xcrun -sdk <sdk> lldb -c core <dsympath>/mach_kernel

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
option. Then run `diff` on the outputs of the baseline and both Python 2 and 3:

* No environment variables to get baseline
* Python 2 with changes
* Python 3 with changes

There may be different ordering of elements based on internal implementation differences of each
Python runtime. Some macros produce files — check the actual file contents.

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
$ pip install --user coverage
$ pip3 install --user coverage
```

Then collect coverage:.

```
# 1. Start LLDB with your macros as described above.

# 2. Load and start code coverage recording.
(lldb) script import coverage
(lldb) script cov = coverage.Coverage()
(lldb) script cov.start()

# 3. Do the testing.

# 4. Collect the coverage.
(lldb) script cov.stop()
(lldb) script cov.save()
```

You can override the default file (*.coverage*) by adding an additional environment variable to LLDB:

```
$ env COVERAGE_FILE="${OUTDIR}/.coverage.mytest.py2" # usual LLDB command line
```

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

### Performance testing

Some macros can run for a long time. Some code may be costly even if it looks simple because objects
aren’t cached or too many temporary objects are created. Simple profiling is similar to collecting
code coverage.

Run this in LLDB to get a profile:

```
# Python 2 example (Python 3 is slightly different)
(lldb) script import cProfile, pstats, StringIO
(lldb) script pr = cProfile.Profile()
(lldb) script pr.enable()
# Run the macro here:
(lldb) showcurrentstacks
(lldb) script pr.disable()
(lldb) script s = StringIO.StringIO()
(lldb) script ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
(lldb) script ps.print_stats()
(lldb) script print(s.getvalue())
```

This will use a function call profiler to collect information about which functions took the most
time during the macro’s execution. For example:

```

        1292170 function calls (1291646 primitive calls) in 3.425 seconds

  Ordered by: cumulative time

  ncalls  tottime  percall  cumtime  percall filename:lineno(function)
       1    0.000    0.000    3.424    3.424 <src>/tools/lldbmacros/xnu.py:104(_internal_command_function)
       1    0.000    0.000    3.424    3.424 <src>/tools/lldbmacros/process.py:1389(ShowCurrentStacks)
       6    0.002    0.000    2.031    0.338 <src>/tools/lldbmacros/xnu.py:358(GetThreadBackTrace)
     467    0.003    0.000    1.969    0.004 <src>/tools/lldbmacros/core/cvalue.py:464(cast)
       1    0.000    0.000    1.757    1.757 <src>/tools/lldbmacros/xnu.py:323(GetKextSymbolInfo)
       1    0.006    0.006    1.756    1.756 <src>/tools/lldbmacros/memory.py:2181(GetKextLoadInformation)
     256    0.000    0.000    1.711    0.007 <src>/tools/lldbmacros/utils.py:142(Cast)
     473    0.002    0.000    1.365    0.003 <src>/tools/lldbmacros/core/cvalue.py:500(gettype)
      30    0.000    0.000    1.342    0.045 .../LLDB.framework/Resources/Python2/lldb/__init__.py:10442(FindTypes)
      30    1.342    0.045    1.342    0.045 {lldb._lldb.SBTarget_FindTypes}
       6    0.000    0.000    1.129    0.188 <src>/tools/lldbmacros/process.py:324(GetThreadSummary)
       6    0.000    0.000    1.106    0.184 <src>/tools/lldbmacros/process.py:312(GetThreadName)
     210    0.027    0.000    0.634    0.003 <src>/tools/lldbmacros/memory.py:2123(GetKmodWithAddr)
     467    0.005    0.000    0.600    0.001 <src>/tools/lldbmacros/core/cvalue.py:343(_GetValueAsCast)
```

## Debugging your changes

YES, It is possible to use a debugger to debug your code!

The steps are similar to testing techniques described above (use scrpting interactive mode). There is no point to
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
