#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'


class INVALID_VALUE_TYPE(Exception):
    """Generic exception for invalid value type specified."""
    pass


class INVALID_FIELD_TYPE(Exception):
    """Generic exception for invalid field type specified."""
    pass


class MISSING_FIELD(Exception):
    """Generic exception for missing fields."""
    pass
