import sys

_names = sys.builtin_module_names

from posix import *
try:
    from posix import _exit
except ImportError:
    pass

del _names

try:
    environ
except NameError:
    environ = {}

