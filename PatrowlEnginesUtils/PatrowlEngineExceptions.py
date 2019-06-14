# -*- coding: utf-8 -*-
"""This file manage Exceptions raised by PatrowlEngine."""


class PatrowlEngineExceptions(Exception):
    """
    This class is all about exceptions based directly on PatrowlEnginese.

    It will consist of a **code** and a **message** describing the reason of
    the exception shortly.
    """

    _error_codes = {
        1000: 'Configuration file not found.',
        1001: 'Report file not found.',
        1002: 'Scan_id not found in current scans.',
        1003: 'Scan not finished.',
    }

    def __init__(self, code, msg=None):
        """Initialise a new PatrowlEngineExceptions."""
        Exception.__init__(self)
        self.code = code
        if msg:
            self.message = msg
        else:
            self.message = self._error_codes.get(code)

    def __str__(self):
        """Return a string-formated object."""
        return "Error %i: %s" % (self.code, self.message)

    def to_dict(self):
        """Return a dict-formated object."""
        return {
            "code": self.code,
            "message": self.message,
            "status": "ERROR"
        }
