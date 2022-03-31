"""
Core classes and functions used for lldb kernel debugging.
"""
from __future__ import absolute_import

from future.utils import PY2, PY3
from .cvalue import value
from .compat import valueint as int
