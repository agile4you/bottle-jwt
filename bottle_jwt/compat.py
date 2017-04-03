# -*- coding: utf-8 -*-
"""`bottle_jwt.compat` module.

Provides python 2, 3 compatibility functions.
"""

from __future__ import unicode_literals
from __future__ import print_function

import sys
import codecs


if sys.version_info.major > 2:
    from inspect import signature as _signature
    signature = _signature

    def b(string):
        return string

else:
    from inspect import getargspec

    class _Signature(object):
        def __init__(self, callable_obj):
            self.spec = getargspec(callable_obj).args

        @property
        def parameters(self):
            return [arg for arg in self.spec if arg != 'self']

    signature = _Signature

    def b(string):
        return codecs.latin_1_encode(string)[0]
