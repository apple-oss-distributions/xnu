"""
Comaptibility layer to support both Python 2 and Python 3 runtimes.
"""
from __future__ import absolute_import

from future.builtins import int
from future.utils import with_metaclass, PY3

if PY3:
    # Python 3 does not have long. Map it to int.
    long = int


class BaseValueInt(type):
    """ Metaclass for valueint.

        Allows to use valueint in places where long/int is expected.
    """

    def __instancecheck__(cls, instance):
        if cls == valueint:
            # Special case for Py2 short or long int
            return isinstance(instance, (int, long))

        return issubclass(instance.__class__, cls)


# The class below inherits form int on Python 3 (see the long = int above).
# In Python 2 mode it becames children of future's newint.
class valueint(with_metaclass(BaseValueInt, long)):
    """ Python 2/3 compatible integer that works with value class.

        The newint from future mostly works but does not implement all
        operators correctly so it breaks support for value class in Python 2.
    """

    def __floordiv__(self, other):
        """ Fix up // operator.

            newint class tries to construct newint even though the __floordiv__
            has returned NotImplemented. It is required to catch the exception
            and retry with __rfloordiv__.
        """
        try:
            result = super(valueint, self).__floordiv__(other)
        except TypeError:
            return other.__rfloordiv__(self)
        return result

    # The __rfloordiv__ operator has similar problem as __floordiv__ because it
    # does not forward to reverse operator. However it is not causing any extra
    # problems because expressions in form of valueint // value are always
    # handled by value class which converts second argument to int.
