#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from future.utils import iteritems
import datetime
import dicttoxml
import json

# import logging
# logging.basicConfig(level=logging.DEBUG)


class Response(object):

    """Base client that all response clients will inherit from."""

    def __init__(self, response):
        """Initial loading of the client.

        :param str api_key: API key from PassiveTotal.org
        """
        self._results = response
        self._boost_properties()

    @classmethod
    def process(inferred, results):
        """Process results and return a loaded instance.

        :param object inferred: Instance of the class itself
        :param dict record: Record to use for loading
        :return: Instance of the loaded class
        """
        return inferred(results)

    def _boost_properties(self):
        """Make first-class keys attributes of the object."""
        for key, value in iteritems(self._results):
            setattr(self, key, value)

    def _load_time(self, time_period, date_format):
        """Convert a str date to true datetime.

        :param str time_period: Date period of the record
        :return: Loaded datetime object from the string
        """
        return datetime.datetime.strptime(
            time_period, date_format
        )

    @property
    def xml(self):
        """Output data as XML.

        :return: XML formatted results
        """
        return dicttoxml.dicttoxml(self._results)

    @property
    def json(self):
        """Output data as JSON.

        :return: Loaded JSON results
        """
        return json.dumps(
            self._results,
            indent=4,
            separators=(',', ': ')
        )

    @property
    def csv(self):
        """Output data as CSV.

        :return: String of formatted data
        """
        raise NotImplementedError("Subclass must implement this.")

    @property
    def text(self):
        """Output data as text.

        :return: String of formatted data
        """
        raise NotImplementedError("Subclass must implement this.")

    @property
    def table(self):
        """Output data as table.

        :return: Table of formatted data
        """
        raise NotImplementedError("Subclass must implement this.")

    @property
    def stix(self):
        """Output data as STIX.

        :return: STIX formatted data
        """
        raise NotImplementedError("Subclass must implement this.")