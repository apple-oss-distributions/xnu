"""
A basic caching module for xnu debug macros to use.


When to use caching?
~~~~~~~~~~~~~~~~~~~~

Very often you do not need to: LLDB already provides extensive data caching.

The most common things that need caching are:
- types (the gettype() function provides this)
- globals (kern.globals / kern.GetGlobalVariable() provides this)


If your macro is slow to get some data, before slapping a caching decorator,
please profile your code using `xnudebug profile`. Very often slowness happens
due to the usage of CreateValueFromExpression() which spins a full compiler
to parse relatively trivial expressions and is easily 10-100x as slow as
alternatives like CreateValueFromAddress().

Only use caching once you have eliminated those obvious performance hogs
and an A/B shows meaningful speed improvements over the base line.


I really need caching how does it work?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides function decorators to easily cache the result of
functions based on their parameters, while keeping the caches separated
per lldb target.

@cache_statically can be used to cache data once per target,
because it won't change if the process is resumed and stopped again.
For example: types, constant values, global addresses, ...

@cache_dynamically can be used to cache data that is expensive to compute
but which content depends on the state of the process. It will be
automatically invalidated for you if the process is resumed and
then stops or hits a breakpoint.

@dyn_cached_property can be used on instances to turn a member into
a per-target cached dynamic property that will be cleaned up when
the object dies or if the process is resumed and then stops
or hits a breakpoint.

Functions using these decorators, must have a `target=None` named argument
that no caller of those functions need to pass explicitly, the decorator
will take care of passing the proper current target value (equivalent to
LazyTarget.GetTarget() except more efficiently).


Cache Invalidation
~~~~~~~~~~~~~~~~~~

This module make the crucial assumption that no XNU lldb macro
will step/resume/... processes as the invalidation only happens
when a new command is being run.

If some macro needs to step/resume it has to provide its own
cache invalidation, by e.g. pushing its own ImplicitContext()
around such process state manipulations.
"""

# Private Routines and objects
from collections import namedtuple

import functools
import gc
import inspect
import sys
import weakref

import lldb

from .configuration import config
from . import lldbwrap


class _Registry(list):
    """ Private class that holds a list of _Cache instances """

    __slots__ = ('name')

    def __init__(self, name):
        super().__init__()
        self.name = name

    @property
    def size(self):
        return sys.getsizeof(self)

    def invalidate(self, pid):
        for cache in self:
            cache.invalidate(pid)

    def clear(self):
        for cache in self:
            cache.clear()

    def __repr__(self):
        return "_Registry({}, {})".format(
            self.name, super().__repr__())

    def __str__(self):
        return "_Registry({}, {} caches, size {})".format(
            self.name, len(self), self.size)


class _Cache(dict):
    """ Private class that implements a given global function _Cache

        Those are created with the @cache_statically/@cache_dynamically
        decorators
    """

    __slots__ = ('name')

    def __init__(self, name, registry):
        super().__init__()
        self.name = name
        registry.append(self)

    @property
    def size(self):
        return sys.getsizeof(self)

    def invalidate(self, pid):
        if pid in self: del self[pid]

    def __repr__(self):
        return "_Cache({}, {})".format(
            self.name, super().__repr__())

    def __str__(self):
        return "_Cache({}, {} entries, size {})".format(
            self.name, len(self), self.size)


_static_registry     = _Registry('static')
_dynamic_registry    = _Registry('dynamic')
_dynamic_keys        = {}

_implicit_target     = None
_implicit_process    = None
_implicit_exe_id     = None
_implicit_dynkey     = None


class _DynamicKey(object):
    """ Wraps a process StopID as a key that can be used as caches keys """

    def __init__(self, exe_id, stop_id):
        self.exe_id  = exe_id
        self.stop_id = stop_id

    def __hash__(self):
        return id(self)


class LazyTarget(object):
    """ A common object that lazy-evaluates and caches the lldb.SBTarget
        and lldb.SBProcess for the current interactive debugging session.
    """

    @staticmethod
    def _CacheUpdateAnchor(exe_id, process):
        global _dynamic_keys, _dynamic_registry

        stop_id = process.GetStopID()
        dyn_key = _dynamic_keys.get(exe_id)

        if dyn_key is None:
            _dynamic_keys[exe_id] = dyn_key = _DynamicKey(exe_id, stop_id)
        elif dyn_key.stop_id != stop_id:
            _dynamic_registry.invalidate(exe_id)
            _dynamic_keys[exe_id] = dyn_key = _DynamicKey(exe_id, stop_id)
            gc.collect()

        return dyn_key

    @staticmethod
    def _CacheGC():
        global _dynamic_keys, _dynamic_registry, _static_registry

        exe_ids = _dynamic_keys.keys() - set(
            tg.GetProcess().GetUniqueID()
            for tg in lldb.debugger
        )

        for exe_id in exe_ids:
            _static_registry.invalidate(exe_id)
            _dynamic_registry.invalidate(exe_id)
            del _dynamic_keys[exe_id]

        if len(exe_ids):
            gc.collect()

    @staticmethod
    def _CacheGetDynamicKey():
        """ Get a _DynamicKey for the most likely current process
        """
        global _implicit_dynkey

        dyn_key = _implicit_dynkey
        if dyn_key is None:
            process = lldbwrap.GetProcess()
            exe_id  = process.GetUniqueID()
            dyn_key = LazyTarget._CacheUpdateAnchor(exe_id, process)

        return dyn_key

    @staticmethod
    def _CacheClear():
        """ remove all cached data.
        """
        global _dynamic_registry, _static_registry, _dynamic_keys

        _dynamic_registry.clear()
        _static_registry.clear()
        _dynamic_keys.clear()

    @staticmethod
    def _CacheSize():
        """ Returns number of bytes held in cache.
            returns:
                int - size of cache including static and dynamic
        """
        global _dynamic_registry, _static_registry

        return _dynamic_registry.size + _static_registry.size


    @staticmethod
    def GetTarget():
        """ Get the SBTarget that is the most likely current target
        """
        global _implicit_target

        return _implicit_target or lldbwrap.GetTarget()

    @staticmethod
    def GetProcess():
        """ Get an SBProcess for the most likely current process
        """
        global _implicit_process

        return _implicit_process or lldbwrap.GetProcess()


class ImplicitContext(object):
    """ This class sets up the implicit target/process
        being used by the XNu lldb macros system.

        In order for lldb macros to function properly, such a context
        must be used around code being run, otherwise macros will try
        to infer it from the current lldb selected target which is
        incorrect in certain contexts.

        typical usage is:

            with ImplicitContext(thing):
                # code

        where @c thing is any of an SBExecutionContext, an SBValue,
        an SBBreakpoint, an SBProcess, or an SBTarget.
    """

    __slots__ = ('target', 'process', 'exe_id', 'old_ctx')

    def __init__(self, arg):
        if isinstance(arg, lldb.SBExecutionContext):
            exe_ctx = lldbwrap.SBExecutionContext(arg)
            target  = exe_ctx.GetTarget()
            process = exe_ctx.GetProcess()
        elif isinstance(arg, lldb.SBValue):
            target  = lldbwrap.SBTarget(arg.GetTarget())
            process = target.GetProcess()
        elif isinstance(arg, lldb.SBBreakpoint):
            bpoint  = lldbwrap.SBBreakpoint(arg)
            target  = bpoint.GetTarget()
            process = target.GetProcess()
        elif isinstance(arg, lldb.SBProcess):
            process = lldbwrap.SBProcess(arg)
            target  = process.GetTarget()
        elif isinstance(arg, lldb.SBTarget):
            target  = lldbwrap.SBTarget(arg)
            process = target.GetProcess()
        else:
            raise TypeError("argument type unsupported {}".format(
                arg.__class__.__name__))

        self.target  = target
        self.process = process
        self.exe_id  = process.GetUniqueID()
        self.old_ctx = None

    def __enter__(self):
        global _implicit_target, _implicit_process, _implicit_exe_id
        global _implicit_dynkey, _dynamic_keys

        self.old_ctx = (_implicit_target, _implicit_process, _implicit_exe_id)

        _implicit_target  = self.target
        _implicit_process = process = self.process
        _implicit_exe_id  = exe_id = self.exe_id
        _implicit_dynkey  = LazyTarget._CacheUpdateAnchor(exe_id, process)

        if len(_dynamic_keys) > 1:
            LazyTarget._CacheGC()

    def __exit__(self, *args):
        global _implicit_target, _implicit_process, _implicit_exe_id
        global _implicit_dynkey, _dynamic_keys

        target, process, exe_id = self.old_ctx
        self.old_ctx = None

        _implicit_target  = target
        _implicit_process = process
        _implicit_exe_id  = exe_id

        if process:
            _implicit_dynkey = LazyTarget._CacheUpdateAnchor(exe_id, process)
        else:
            _implicit_dynkey = None


class _HashedSeq(list):
    """ This class guarantees that hash() will be called no more than once
        per element.  This is important because the lru_cache() will hash
        the key multiple times on a cache miss.

        Inspired by python3's lru_cache decorator implementation
    """

    __slots__ = 'hashvalue'

    def __init__(self, tup, hash=hash):
        self[:] = tup
        self.hashvalue = hash(tup)

    def __hash__(self):
        return self.hashvalue

    @classmethod
    def make_key(cls, args, kwds, kwd_mark = (object(),),
        fasttypes = {int, str}, tuple=tuple, type=type, len=len):

        """ Inspired from python3's cache implementation """

        key = args
        if kwds:
            key += kwd_mark
            key += tuple(kwd.items())
        elif len(key) == 0:
            return None
        elif len(key) == 1 and type(key[0]) in fasttypes:
            return key[0]
        return cls(key)


def _cache_with_registry(fn, registry, maxsize=1024, sentinel=object()):
    """ Internal function """

    nokey = False

    if hasattr(inspect, 'signature'): # PY3
        sig = inspect.signature(fn)
        tg  = sig.parameters.get('target')
        if not tg or tg.default is not None:
            raise ValueError("function doesn't have a 'target=None' argument")

        nokey = len(sig.parameters) == 1
        cache = _Cache(fn.__qualname__, registry)
    else:
        spec = inspect.getargspec(fn)
        try:
            index = spec.args.index('target')
            offs  = len(spec.args) - len(spec.defaults)
            if index < offs or spec.defaults[index - offs] is not None:
                raise ValueError
        except:
            raise ValueError("function doesn't have a 'target=None' argument")

        nokey = len(spec.args) == 1 and spec.varargs is None and spec.keywords is None
        cache = _Cache(fn.__name__, registry)

    c_setdef = cache.setdefault
    c_get    = cache.get
    make_key = _HashedSeq.make_key
    getdynk  = LazyTarget._CacheGetDynamicKey
    gettg    = LazyTarget.GetTarget

    if nokey:
        def caching_wrapper(*args, **kwds):
            global _implicit_exe_id, _implicit_target

            key = _implicit_exe_id or getdynk().exe_id
            result = c_get(key, sentinel)
            if result is not sentinel:
                return result

            kwds['target'] = _implicit_target or gettg()
            return c_setdef(key, fn(*args, **kwds))

        def cached(*args, **kwds):
            global _implicit_exe_id

            return c_get(_implicit_exe_id or getdynk().exe_id, sentinel) != sentinel
    else:
        def caching_wrapper(*args, **kwds):
            global _implicit_exe_id, _implicit_target

            tg_d   = c_setdef(_implicit_exe_id or getdynk().exe_id, {})
            c_key  = make_key(args, kwds)
            result = tg_d.get(c_key, sentinel)
            if result is not sentinel:
                return result

            #
            # Blunt policy to avoid exploding memory,
            # that is simpler than an actual LRU.
            #
            # TODO: be smarter?
            #
            if len(tg_d) >= maxsize: tg_d.clear()

            kwds['target'] = _implicit_target or gettg()
            return tg_d.setdefault(c_key, fn(*args, **kwds))

        def cached(*args, **kwds):
            global _implicit_exe_id

            tg_d = c_get(_implicit_exe_id or getdynk().exe_id)
            return tg_d and tg_d.get(make_key(args, kwds), sentinel) != sentinel

    caching_wrapper.cached = cached
    return functools.update_wrapper(caching_wrapper, fn)


def cache_statically(fn):
    """ Decorator to cache the results statically

        This basically makes the decorated function cache its result based
        on its arguments with an automatic static per target cache

        The function must have a named parameter called 'target' defaulting
        to None, with no clients ever passing it explicitly.  It will be
        passed the proper SBTarget when called.

        @cache_statically(user_function)
            Cache the results of this function automatically per target,
            using the arguments of the function as the cache key.
    """

    return _cache_with_registry(fn, _static_registry)


def cache_dynamically(fn):
    """ Decorator to cache the results dynamically

        This basically makes the decorated function cache its result based
        on its arguments with an automatic dynamic cache that is reset
        every time the process state changes

        The function must have a named parameter called 'target' defaulting
        to None, with no clients ever passing it explicitly.  It will be
        passed the proper SBTarget when called.

        @cache_dynamically(user_function)
            Cache the results of this function automatically per target,
            using the arguments of the function as the cache key.
    """

    return _cache_with_registry(fn, _dynamic_registry)


def dyn_cached_property(fn, sentinel=object()):
    """ Decorator to make a class or method property cached per instance

        The method must have the prototype:

            def foo(self, target=None)

        and will generate the property "foo".
    """

    if hasattr(inspect, 'signature'): # PY3
        if list(inspect.signature(fn).parameters) != ['self', 'target']:
            raise ValueError("function signature must be (self, target=None)")
    else:
        spec = inspect.getargspec(fn)
        if spec.args != ['self', 'target'] or \
                spec.varargs is not None or spec.keywords is not None:
            raise ValueError("function signature must be (self, target=None)")

    getdynk  = LazyTarget._CacheGetDynamicKey
    gettg    = LazyTarget.GetTarget
    c_attr   = "_dyn_key__" + fn.__name__

    def dyn_cached_property_wrapper(self, target=None):
        global _implicit_dynkey, _implicit_target

        cache = getattr(self, c_attr, None)
        if cache is None:
            cache = weakref.WeakKeyDictionary()
            setattr(self, c_attr, cache)

        c_key  = _implicit_dynkey or getdynk()
        result = cache.get(c_key, sentinel)
        if result is not sentinel:
            return result

        return cache.setdefault(c_key, fn(self, _implicit_target or gettg()))

    return property(functools.update_wrapper(dyn_cached_property_wrapper, fn))


ClearAllCache = LazyTarget._CacheClear

GetSizeOfCache = LazyTarget._CacheSize

__all__ = [
    LazyTarget.__name__,
    ImplicitContext.__name__,

    cache_statically.__name__,
    cache_dynamically.__name__,
    dyn_cached_property.__name__,

    ClearAllCache.__name__,
    GetSizeOfCache.__name__,
]
