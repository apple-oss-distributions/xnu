import getopt
import os
import string
import sys
import re

from lldb import SBValue, SBCommandReturnObject
from core import value as cvalue
from .configuration import config

HELP_ARGUMENT_EXCEPTION_SENTINEL = "HELP"

class ArgumentError(Exception):
    """ Exception class for raising errors in command arguments. The lldb_command framework will catch this
        class of exceptions and print suitable error message to user.
    """
    def __init__(self, msg="Bad arguments provided"):
        self.error_message = msg
    def __str__(self):
        return str(self.error_message)


class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    def __exit__(self, exc_type, exc_value, traceback):
        self._stdout.flush(); self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr

class IndentScope(object):
    def __init__(self, O):
        self._O = O

    def __enter__(self):
        self._O._indent += '    '

    def __exit__(self, exc_type, exc_value, traceback):
        self._O._indent = self._O._indent[:-4]

class HeaderScope(object):
    def __init__(self, O, hdr, indent = False):
        self._O = O
        self._header = hdr
        self._indent = indent

    def __enter__(self):
        self._oldHeader = self._O._header
        self._oldLastHeader = self._O._lastHeader
        self._O._header = self._header
        self._O._lastHeader = None
        if self._indent:
            self._O._indent += '    '

    def __exit__(self, exc_type, exc_value, traceback):
        self._O._header = self._oldHeader
        self._O._lastHeader = self._oldLastHeader
        if self._indent:
            self._O._indent = self._O._indent[:-4]

class VT(object):
    Black        = "\033[38;5;0m"
    DarkRed      = "\033[38;5;1m"
    DarkGreen    = "\033[38;5;2m"
    Brown        = "\033[38;5;3m"
    DarkBlue     = "\033[38;5;4m"
    DarkMagenta  = "\033[38;5;5m"
    DarkCyan     = "\033[38;5;6m"
    Grey         = "\033[38;5;7m"

    DarkGrey     = "\033[38;5;8m"
    Red          = "\033[38;5;9m"
    Green        = "\033[38;5;10m"
    Yellow       = "\033[38;5;11m"
    Blue         = "\033[38;5;12m"
    Magenta      = "\033[38;5;13m"
    Cyan         = "\033[38;5;14m"
    White        = "\033[38;5;15m"

    Default      = "\033[39m"

    Bold         = "\033[1m"
    EndBold      = "\033[22m"

    Oblique      = "\033[3m"
    EndOblique   = "\033[23m"

    Underline    = "\033[4m"
    EndUnderline = "\033[24m"

    Reset        = "\033[0m"

class NOVT(object):
    def __getattribute__(self, *args):
        return ""

class SBValueFormatter(string.Formatter):
    """
    Formatter that treats SBValues specially

    It adds the following magical syntax for fields:

    - {$value->path.to[10].field} will follow a given expression path,
      and compute the resulting SBValue. This works with cvalues too.

    - {&value->path.to[10].field} will return the load address
      of the specified value path. This works with cvalue too.


    The format spec can now take a multi-char conversion,
    {field|<multi-char-conversion>!conv:spec},
    where <multi-char-conversion> is one of:

    - `c_str` which will attempt to read the value as a C string using
      xGetValueAsCString()

    - `human_size` will convert sizes into a human readable representation.

    - a conversion registered with the SBValueFormatter.converter
      decorator,

    - a `key.method` specification where the key is one of the positional
      or named arguments to the format.


    When the value of a given field is an SBValue (because &/$ was used,
    or the field was already an SBValue -- but not a cvalue), in the absence
    of a explicit conversion, the SBValue will be converted to a scalar
    using xGetValueAsScalar()
    """

    _KEY_RE = re.compile(r"[.-\[]")

    _CONVERTERS = {}

    @classmethod
    def converter(cls, name, raw=False):
        def register(fn):
            cls._CONVERTERS[name] = (fn, raw)

        return register

    def format(self, format_string, *args, **kwargs):
        return self.vformat(self, format_string, args, kwargs)

    def _raise_switch_manual_to_automatic(self):
        raise ValueError('cannot switch from manual field '
                         'specification to automatic field '
                         'numbering')

    def vformat(self, format_string, args, kwargs):
        result    = []
        auto_idx  = 0

        #
        # Python 2.7 doesn't support empty field names in Formatter,
        # so we need to implement vformat. Because we avoid certain
        # features such as "unused fields accounting" we actually
        # are faster than the core library Formatter this way which
        # adds up quickly for our macros, so it's worth keeping
        # this implementation even on Python 3.
        #
        for text, field_name, format_spec, conv in \
                self.parse(format_string):

            if text:
                result.append(text)

            if field_name is None:
                continue

            field_name, _, transform = field_name.partition('|')

            if field_name == '':
                #
                # Handle auto-numbering like python 3
                #
                if auto_idx is None:
                    self._raise_switch_manual_to_automatic()
                field_name = str(auto_idx)
                auto_idx  += 1

            elif field_name.isdigit():
                #
                # numeric key
                #
                if auto_idx:
                    self._raise_switch_manual_to_automatic()
                auto_idx = None

            try:
                if field_name[0] in '&$':
                    #
                    # Our magic sigils
                    #
                    obj, auto_idx = self.get_value_field(
                        field_name, args, kwargs, auto_idx)

                else:
                    #
                    # Fallback typical case
                    #
                    obj, _ = self.get_field(field_name, args, kwargs)
            except:
                if config['debug']: raise
                result.extend((
                    VT.Red,
                    "<FAIL {}>".format(field_name),
                    VT.Reset
                ))
                continue

            # do any conv on the resulting object
            try:
                obj = self.convert_field(obj, conv, transform, args, kwargs)
            except:
                if config['debug']: raise
                result.extend((
                    VT.Red,
                    "<CONV {}>".format(field_name),
                    VT.Reset
                ))
                continue

            result.append(self.format_field(obj, format_spec))

        return ''.join(result)

    def get_value_field(self, name, args, kwargs, auto_idx):
        match = self._KEY_RE.search(name)
        index = match.start() if match else len(name)
        key   = name[1:index]
        path  = name[index:]

        if key == '':
            raise ValueError("Key part of '{}' can't be empty".format(name))

        if key.isdigit():
            key = int(key)
            if auto_idx:
                self._raise_switch_manual_to_automatic()
            auto_idx = None

        obj = self.get_value(key, args, kwargs)
        if isinstance(obj, cvalue):
            obj = obj.GetSBValue()

        if name[0] == '&':
            if len(path):
                return obj.xGetLoadAddressByPath(path), auto_idx
            return obj.GetLoadAddress(), auto_idx

        if len(path):
            obj = obj.GetValueForExpressionPath(path)
        return obj, auto_idx

    def convert_field(self, obj, conv, transform='', args=None, kwargs=None):
        is_sbval = isinstance(obj, SBValue)

        if transform != '':
            fn, raw = self._CONVERTERS.get(transform, (None, False))
            if not raw and is_sbval:
                obj = obj.xGetValueAsScalar()

            if fn:
                obj = fn(obj)
            else:
                objname, _, method = transform.partition('.')
                field, _ = self.get_field(objname, args, kwargs)
                obj = getattr(field, method)(obj)

            is_sbval = False

        if conv is None:
            return obj.xGetValueAsScalar() if is_sbval else obj

        return super(SBValueFormatter, self).convert_field(obj, conv)

@SBValueFormatter.converter("c_str", raw=True)
def __sbval_to_cstr(v):
    return v.xGetValueAsCString() if isinstance(v, SBValue) else str(v)

@SBValueFormatter.converter("human_size")
def __human_size(v):
    n = v.xGetValueAsCString() if isinstance(v, SBValue) else int(v)
    order = ((n//10) | 1).bit_length() // 10
    return "{:.1f}{}".format(n / (1024 ** order), "BKMGTPE"[order])


_xnu_core_default_formatter = SBValueFormatter()

def xnu_format(fmt, *args, **kwargs):
    """ Conveniency function to call SBValueFormatter().format """
    return _xnu_core_default_formatter.vformat(fmt, args, kwargs)

def xnu_vformat(fmt, args, kwargs):
    """ Conveniency function to call SBValueFormatter().vformat """
    return _xnu_core_default_formatter.vformat(fmt, args, kwargs)


class CommandOutput(object):
    """
    An output handler for all commands. Use Output.print to direct all output of macro via the handler.
    These arguments are passed after a "--". eg
    (lldb) zprint -- -o /tmp/zprint.out.txt

    Currently this provide capabilities
    -h show help
    -o path/to/filename
       The output of this command execution will be saved to file. Parser information or errors will
       not be sent to file though. eg /tmp/output.txt
    -s filter_string
       the "filter_string" param is parsed to python regex expression and each line of output
       will be printed/saved only if it matches the expression.
       The command header will not be filtered in any case.
    -p <plugin_name>
       Send the output of the command to plugin.
    -v ...
       Up verbosity
    -c <always|never|auto>
       configure color
    """
    def __init__(self, cmd_name: str, CommandResult: SBCommandReturnObject=None, fhandle=None):
        """ Create a new instance to handle command output.
        params:
                CommandResult : SBCommandReturnObject result param from lldb's command invocation.
        """
        self.fname=None
        self.fhandle=fhandle
        self.FILTER=False
        self.pluginRequired = False
        self.pluginName = None
        self.cmd_name = cmd_name
        self.resultObj = CommandResult
        self.verbose_level = 0
        self.target_cmd_args = []
        self.target_cmd_options = {}
        self._indent = ''
        self._buffer = ''

        self._header = None
        self._lastHeader = None
        self._line = 0

        self.color = None
        self.isatty = os.isatty(sys.__stdout__.fileno())
        self.VT = VT if self._doColor() else NOVT()


    def _doColor(self):
        if self.color is True:
            return True;
        return self.color is None and self.isatty

    def _needsHeader(self):
        if self._header is None:
            return False
        if self._lastHeader is None:
            return True
        if not self.isatty:
            return False
        return self._line - self._lastHeader > 40

    def indent(self):
        return IndentScope(self)

    def table(self, header, indent = False):
        return HeaderScope(self, header, indent)

    def format(self, s, *args, **kwargs):
        kwargs['VT'] = self.VT
        return xnu_vformat(s, args, kwargs)

    def error(self, s, *args, **kwargs):
        print(self.format("{cmd.cmd_name}: {VT.Red}"+s+"{VT.Default}", cmd=self, *args, **kwargs))

    def write(self, s):
        """ Handler for all commands output. By default just print to stdout """

        o = self.fhandle or self.resultObj

        for l in (self._buffer + s).splitlines(True):
            if l[-1] != '\n':
                self._buffer = l
                return

            if self.FILTER:
                if not self.reg.search(l):
                    continue
                l = self.reg.sub(self.VT.Underline + r"\g<0>" + self.VT.EndUnderline, l);

            if len(l) == 1:
                o.write(l)
                self._line += 1
                continue

            if len(l) > 1 and self._needsHeader():
                for h in self._header.splitlines():
                    o.write(self.format("{}{VT.Bold}{:s}{VT.EndBold}\n", self._indent, h))
                self._lastHeader = self._line

            o.write(self._indent + l)
            self._line += 1

        self._buffer = ''

    def flush(self):
        if self.fhandle != None:
            self.fhandle.flush()

    def __del__(self):
        """ closes any open files. report on any errors """
        if self.fhandle != None and self.fname != None:
            self.fhandle.close()

    def setOptions(self, cmdargs, cmdoptions =''):
        """ parse the arguments passed to the command
            param :
                cmdargs => [] of <str> (typically args.split())
                cmdoptions : str - string of command level options.
                             These should be CAPITAL LETTER options only.
        """
        opts=()
        args = cmdargs
        cmdoptions = cmdoptions.upper()
        try:
            opts,args = getopt.gnu_getopt(args,'hvo:s:p:c:'+ cmdoptions,[])
            self.target_cmd_args = args
        except getopt.GetoptError as err:
            raise ArgumentError(str(err))
        #continue with processing
        for o,a in opts :
            if o == "-h":
                # This is misuse of exception but 'self' has no info on doc string.
                # The caller may handle exception and display appropriate info
                raise ArgumentError(HELP_ARGUMENT_EXCEPTION_SENTINEL)
            if o == "-o" and len(a) > 0:
                self.fname=os.path.normpath(os.path.expanduser(a.strip()))
                self.fhandle=open(self.fname,"w")
                print("saving results in file ",str(a))
                self.fhandle.write("(lldb)%s %s \n" % (self.cmd_name, " ".join(cmdargs)))
                self.isatty = os.isatty(self.fhandle.fileno())
            elif o == "-s" and len(a) > 0:
                self.reg = re.compile(a.strip(),re.MULTILINE|re.DOTALL)
                self.FILTER=True
                print("showing results for regex:",a.strip())
            elif o == "-p" and len(a) > 0:
                self.pluginRequired = True
                self.pluginName = a.strip()
                #print "passing output to " + a.strip()
            elif o == "-v":
                self.verbose_level += 1
            elif o == "-c":
                if a in ["always", '1']:
                    self.color = True
                elif a in ["never", '0']:
                    self.color = False
                else:
                    self.color = None
                self.VT = VT if self._doColor() else NOVT()
            else:
                o = o.strip()
                self.target_cmd_options[o] = a


