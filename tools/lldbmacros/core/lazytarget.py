""" Module to abstract lazy evaluation of lldb.SBTarget
    for kernel
"""
from .caching import LazyTarget

# backward compatibility, this has moved to caching
__all__ = [ LazyTarget.__name__ ]
