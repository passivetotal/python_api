#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from future.utils import iteritems
import datetime
import json
import logging
import sys


class Response(object):

    """Base client that all response clients will inherit from."""

    def __init__(self, response, **kwargs):
        """Initial loading of the client.

        :param str api_key: API key from PassiveTotal.org
        """
        self.logger = logging.getLogger('pt-base-response')
        self.logger.setLevel('INFO')
        shandler = logging.StreamHandler(sys.stdout)
        fmtr = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| %(message)s')
        shandler.setFormatter(fmtr)
        self.logger.addHandler(shandler)
        if 'debug' in kwargs:
            self.logger.setLevel('DEBUG')
        self.logger.debug("Results: %s" % str(response))
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
            self.logger.debug("Property: %s, %s" % (key, value))
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
        """Output data as text.

        :return: XML formatted data
        """
        raise NotImplementedError("Subclass must implement this.")

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